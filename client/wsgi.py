from appli import init_app

app = init_app()

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True, threaded=True, port=8080)
