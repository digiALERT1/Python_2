import subprocess

from vuln_server.outputgrabber import OutputGrabber
from flask import request, redirect, render_template, current_app as app


class SubprocessVuln():

    def bypass(self):
        if request.method == 'POST':
            # Check if data is not empty, post forms has all params defined
            # which may be empty and cause unexpected behaviour.
            if request.form['input_data'] != '':
                try:
                    # Instanciate a different stdout grabber for subprocess
                    output = OutputGrabber()
                    with output:
                        # Execute system command with an unsafe input parameter
                        # Define an allowlist of acceptable inputs
                        ALLOWLIST = {'localhost', '127.0.0.1'}
                        input_data = request.form['input_data']
                        if input_data in ALLOWLIST:
                            subprocess.call(["ping", "-c1", input_data])
                        else:
                            return "Invalid input"
                    return output.capturedtext
                except Exception as e:
                    app.logger.error("Exception occurred", exc_info=True)
                    return "An internal error has occurred!"
            else:
                return redirect(request.url)
        return render_template('subprocess.html')
