import random

from vuln_server.outputgrabber import OutputGrabber
from flask import request, redirect, render_template
from urllib.parse import urlparse


class EvalVuln():

    def bypass(self):
        if request.method == 'POST':
            # Check if data is not empty, post forms has all params defined
            # which may be empty and cause unexpected behaviour.
            if request.form['input_data'] != '':
                data = random.randint(1, 1000)
                try:
                    # Instanciate a different stdout grabber for subprocess
                    output = OutputGrabber()
                    with output:
                        # Eval input data and execute code from it
                        if data != eval(request.form['input_data']):
                            pass
                    return output.capturedtext
                except Exception as e:
                    import logging
                    logging.error("Exception occurred", exc_info=True)
                    return "An internal error has occurred!"
            else:
                target_url = request.url.replace('\\', '')
                if not urlparse(target_url).netloc and not urlparse(target_url).scheme:
                    return redirect(target_url)
                return redirect('/')
        return render_template('eval.html')
