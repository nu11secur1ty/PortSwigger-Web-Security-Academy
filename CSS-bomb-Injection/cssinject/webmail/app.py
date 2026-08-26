from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Simulated inbox with a hidden secret token inside a specific attribute/class
emails = [
    {
        "id": 1,
        "sender": "hr@company.com",
        "subject": "Your Secret Access Key",
        "body": "<p>Hello, your secret vault key is: <span class='secret' data-flag='FLAG{css_bomb_exfiltrated}'>[PROTECTED]</span></p>"
    }
]

@app.route('/')
def inbox():
    return render_template('inbox.html', emails=emails)

@app.route('/send', methods=['POST'])
def send_email():
    sender = request.form.get('sender')
    subject = request.form.get('subject')
    body = request.form.get('body')  # Vulnerable to CSS injection
    
    new_email = {
        "id": len(emails) + 1,
        "sender": sender,
        "subject": subject,
        "body": body
    }
    emails.append(new_email)
    return redirect(url_for('inbox'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
