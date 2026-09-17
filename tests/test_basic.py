import ctf_recon

def test_basic():
    assert ctf_recon is not None

def test_cli_import():
    from ctf_recon.cli import app
    assert app is not None
