# app.py - Main Flask application for the Encrypted Traffic Threat Detector dashboard

import os
import json
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)
from werkzeug.utils import secure_filename

from dashboard.models import db, ThreatRecord, UploadedFile, AppSettings
from dashboard.utils import (
    allowed_file,
    analyze_csv_file,
    analyze_pcap_file,
    generate_mock_monitoring_data,
    get_dashboard_stats,
    get_severity_badge_class,
    get_status_badge_class,
    SEVERITY_LEVELS,
)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # Default configuration
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            'DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "threat_data.db")}'
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=UPLOAD_FOLDER,
        MAX_CONTENT_LENGTH=64 * 1024 * 1024,  # 64 MB
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        _seed_default_settings()

    # Register context processors
    @app.context_processor
    def inject_helpers():
        return {
            'severity_badge': get_severity_badge_class,
            'status_badge': get_status_badge_class,
            'now': datetime.utcnow,
        }

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.route('/')
    def index():
        stats = get_dashboard_stats(db.session, ThreatRecord, UploadedFile)
        return render_template('index.html', **stats)

    @app.route('/upload', methods=['GET', 'POST'])
    def upload():
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file selected.', 'danger')
                return redirect(request.url)

            file = request.files['file']
            if file.filename == '':
                flash('No file selected.', 'danger')
                return redirect(request.url)

            if not allowed_file(file.filename):
                flash('Invalid file type. Please upload a CSV or PCAP file.', 'danger')
                return redirect(request.url)

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            file_size = os.path.getsize(filepath)
            ext = filename.rsplit('.', 1)[1].lower()

            uploaded = UploadedFile(
                filename=filename,
                file_size=file_size,
                file_type=ext,
                status='pending',
            )
            db.session.add(uploaded)
            db.session.commit()

            # Analyze the file
            try:
                if ext == 'csv':
                    threats, row_count = analyze_csv_file(filepath)
                    summary = f'Processed {row_count} rows.'
                else:
                    threats, packet_count = analyze_pcap_file(filepath)
                    summary = f'Processed ~{packet_count} packets.'

                for t in threats:
                    record = ThreatRecord(
                        source_ip=t.get('source_ip'),
                        destination_ip=t.get('destination_ip'),
                        threat_type=t['threat_type'],
                        severity=t['severity'],
                        confidence=t.get('confidence'),
                        description=t.get('description'),
                        protocol=t.get('protocol'),
                        port=t.get('port'),
                    )
                    db.session.add(record)

                uploaded.status = 'analyzed'
                uploaded.threat_count = len(threats)
                uploaded.analysis_summary = summary
                db.session.commit()

                flash(
                    f'File "{filename}" analyzed successfully. '
                    f'{len(threats)} threat(s) detected.',
                    'success',
                )
            except Exception as exc:
                uploaded.status = 'failed'
                db.session.commit()
                flash(f'Analysis failed: {exc}', 'danger')

            return redirect(url_for('analysis'))

        recent_uploads = (
            UploadedFile.query.order_by(UploadedFile.upload_time.desc()).limit(10).all()
        )
        return render_template('upload.html', recent_uploads=recent_uploads)

    @app.route('/analysis')
    def analysis():
        severity_filter = request.args.get('severity', '')
        status_filter = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)

        query = ThreatRecord.query
        if severity_filter and severity_filter in SEVERITY_LEVELS:
            query = query.filter(ThreatRecord.severity == severity_filter)
        if status_filter:
            query = query.filter(ThreatRecord.status == status_filter)

        threats = query.order_by(ThreatRecord.timestamp.desc()).paginate(
            page=page, per_page=20, error_out=False
        )

        severity_counts = {level: 0 for level in SEVERITY_LEVELS}
        for level in SEVERITY_LEVELS:
            severity_counts[level] = ThreatRecord.query.filter(
                ThreatRecord.severity == level
            ).count()

        return render_template(
            'analysis.html',
            threats=threats,
            severity_counts=severity_counts,
            severity_filter=severity_filter,
            status_filter=status_filter,
            severity_levels=SEVERITY_LEVELS,
        )

    @app.route('/monitoring')
    def monitoring():
        monitoring_data = generate_mock_monitoring_data(num_points=20)
        recent_threats = (
            ThreatRecord.query.filter(ThreatRecord.status == 'open')
            .order_by(ThreatRecord.timestamp.desc())
            .limit(10)
            .all()
        )
        return render_template(
            'monitoring.html',
            monitoring_data=json.dumps(monitoring_data),
            recent_threats=recent_threats,
        )

    @app.route('/api/monitoring-data')
    def api_monitoring_data():
        """JSON endpoint polled by the monitoring page for live updates."""
        data = generate_mock_monitoring_data(num_points=1)
        return jsonify(data[0])

    @app.route('/reports')
    def reports():
        uploads = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()
        total_threats = ThreatRecord.query.count()
        severity_counts = {level: 0 for level in SEVERITY_LEVELS}
        for level in SEVERITY_LEVELS:
            severity_counts[level] = ThreatRecord.query.filter(
                ThreatRecord.severity == level
            ).count()
        threat_type_counts = {}
        for record in ThreatRecord.query.with_entities(
            ThreatRecord.threat_type, db.func.count(ThreatRecord.id)
        ).group_by(ThreatRecord.threat_type).all():
            threat_type_counts[record[0]] = record[1]

        return render_template(
            'reports.html',
            uploads=uploads,
            total_threats=total_threats,
            severity_counts=severity_counts,
            threat_type_counts=threat_type_counts,
        )

    @app.route('/settings', methods=['GET', 'POST'])
    def settings():
        if request.method == 'POST':
            keys = [
                'alert_threshold',
                'max_upload_size',
                'retention_days',
                'notification_email',
                'enable_realtime',
            ]
            for key in keys:
                value = request.form.get(key, '')
                setting = AppSettings.query.filter_by(key=key).first()
                if setting:
                    setting.value = value
                else:
                    db.session.add(AppSettings(key=key, value=value))
            db.session.commit()
            flash('Settings saved successfully.', 'success')
            return redirect(url_for('settings'))

        current_settings = {s.key: s.value for s in AppSettings.query.all()}
        return render_template('settings.html', settings=current_settings)

    @app.route('/threats/<int:threat_id>/resolve', methods=['POST'])
    def resolve_threat(threat_id):
        threat = ThreatRecord.query.get_or_404(threat_id)
        threat.status = 'resolved'
        db.session.commit()
        flash(f'Threat #{threat_id} marked as resolved.', 'success')
        return redirect(url_for('analysis'))

    @app.route('/threats/<int:threat_id>/false-positive', methods=['POST'])
    def false_positive(threat_id):
        threat = ThreatRecord.query.get_or_404(threat_id)
        threat.status = 'false_positive'
        db.session.commit()
        flash(f'Threat #{threat_id} marked as false positive.', 'info')
        return redirect(url_for('analysis'))

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(413)
    def file_too_large(e):
        flash('File is too large. Maximum upload size is 64 MB.', 'danger')
        return redirect(url_for('upload'))

    return app


def _seed_default_settings():
    defaults = {
        'alert_threshold': '0.75',
        'max_upload_size': '64',
        'retention_days': '30',
        'notification_email': '',
        'enable_realtime': 'true',
    }
    for key, value in defaults.items():
        if not AppSettings.query.filter_by(key=key).first():
            db.session.add(AppSettings(key=key, value=value))
    db.session.commit()


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug)

