import base64
import json
from vuln_server.outputgrabber import OutputGrabber
from flask import flash, request, redirect, render_template
import logging


logging.basicConfig(level=logging.ERROR)

class PickleVuln():

    def injection(self):
        """Pickle object command injection/execution.

        This funtion will evaluate if the user includes a file or
        a pickle base64 object and load the object.
        """
        if request.method == 'POST':
            # Check if data is not empty, post forms has all params defined
            # which may be empty and cause unexpected behaviour
            if request.form['input_data'] != '':
                try:
                    # Instanciate a different stdout grabber for subprocess
                    output = OutputGrabber()
                    with output:
                        # Load base64 encoded pickle object, output from the
                        # exploit is stored into Outputgrabber stdout
                        json.loads(
                            base64.b64decode(request.form['input_data']).decode('utf-8'))
                    return output.capturedtext
                except Exception as e:
                    logging.error("Exception occurred", exc_info=True)
                    return "An internal error has occurred!"
            elif request.files['file'].filename != '':
                file_data = request.files['file'].read()
                try:
                    output = OutputGrabber()
                    with output:
                        json.loads(base64.b64decode(file_data).decode('utf-8'))
                    return output.capturedtext
                except Exception as e:
                    logging.error("Exception occurred", exc_info=True)
                    return "An internal error has occurred!"
            else:
                flash('No selected file')
                return redirect(request.url)
        return render_template('pickle.html')
