from flask import Flask
from server_anomaly.dashboard.server_dashboard import register_server_dashboard
from network_anomaly.dashboard.network_dashboard import register_network_dashboard
from network_anomaly.dashboard.network_dashboard import register_network_dashboard

def create_app():
    app = Flask(__name__)
    
    # Register blueprints
    register_server_dashboard(app)
    register_network_dashboard(app)  

    ...

    @app.route('/')
    def index():
        return """
        <h1>Anomaly Detection System</h1>
        <ul>
            <li><a href="/server">Server Dashboard</a></li>
            <li><a href="/network">Network Dashboard</a></li>
        </ul>
        """
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)