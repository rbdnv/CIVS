from app.main import app


def test_demo_routes_and_static_mount_are_registered():
    paths = {route.path for route in app.routes}

    assert "/demo/compare" in paths
    assert "/api/v1/demo/session" in paths
    assert "/static" in paths
