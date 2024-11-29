from xml.dom.pulldom import parseString
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges

from flask import request, redirect, render_template
from urllib.parse import urlparse


class XMLVuln():

    def injection(self):
        if request.method == 'POST':
            # Check if data is not empty, post forms has all params defined
            # which may be empty and cause unexpected behaviour
            if request.form['input_data'] != '':
                # Instanciate an XML parser allowing unsafe external
                # sources to to be parsed by xml.parseString
                parser = make_parser()
                parser.setFeature(feature_external_ges, True)
                doc = parseString(request.form['input_data'], parser=parser)
                for event, node in doc:
                    doc.expandNode(node)
                    return(node.toxml())
            else:
                target_url = request.url.replace('\\', '')
                if not urlparse(target_url).netloc and not urlparse(target_url).scheme:
                    return redirect(target_url)
                return redirect('/')
        return render_template('xml.html')
