from defusedxml.pulldom import parseString


from flask import request, redirect, render_template


class XMLVuln():

    def injection(self):
        if request.method == 'POST':
            # Check if data is not empty, post forms has all params defined
            # which may be empty and cause unexpected behaviour
            if request.form['input_data'] != '':
                # Instanciate an XML parser allowing unsafe external
                # sources to to be parsed by xml.parseString
                doc = parseString(request.form['input_data'])
                for event, node in doc:
                    doc.expandNode(node)
                    return(node.toxml())
            else:
                return redirect(request.url)
        return render_template('xml.html')
