from flask import Flask, request, abort

app = Flask(__name__)

# Simples verificação WAF
def waf_detect(payload):
    blacklist = ["'", '"', " or ", " and ", "--", "/*", "*/", "sleep(", "benchmark(", ";"]
    for item in blacklist:
        if item in payload.lower():
            return True
    return False

@app.route('/vulneravel')
def vulneravel():
    param = request.args.get('id', '')
    if waf_detect(param):
        abort(403)  # Forbidden se for detectado
    return f"Parâmetro recebido: {param}"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
