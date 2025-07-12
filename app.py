from flask import Flask, render_template, jsonify
import csv

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    with open('data.csv', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return jsonify(list(reader))

if __name__ == '__main__':
    app.run(debug=True)
