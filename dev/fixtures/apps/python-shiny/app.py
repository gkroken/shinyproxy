import platform

from shiny import App, render, ui

app_ui = ui.page_fluid(ui.output_text("hello"))


def server(input, output, session):
    @render.text
    def hello():
        return "skald python-shiny fixture on Python " + platform.python_version()


app = App(app_ui, server)
