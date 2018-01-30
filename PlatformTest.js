const http = require('http');
const fs = require('fs');

// create a simple HTTP server that will handle the requests
http.createServer((request, response) => {
    const { headers, method, url } = request;
    console.log("Called at " + new Date().toLocaleDateString());
    let body = [];
    request.on('error', (err) => {
        console.log("Svr Error Handler :" + err.toString);
        response.statusCode(400);
        response.end();
    }).on('data', (chunk) => {
        body.push(chunk);
    }).on('end', () => {
        body = Buffer.concat(body).toString();
        // At this point, we have the headers, method, url and body, and can now
        // do whatever we need to in order to respond to this request.

    });

    // record in the console what details have been received
    console.log ("Received:\nMethod:" + method.toString() + 
        "\n URL:"+ url.toString + "\nheaders:\n"+headers.toString() +
        "\nBody:\n" + body);
    // now build the response
    response.setHeader('Content-Type', 'application/json');
    response.setHeader('PlatformTestTime', new Date().toLocaleDateString());

    // initialise our response object so that if we don't load a response
    // file then we reflect the content
    var responseBody = { headers, method, url, body };

    try {
        // try reading a response file
        fs.readFile('testResponse.json', function(err, data) {
            console.log("handling file");
            if (err != null) {
                if (err.code === 'ENOENT') {
                    console.log("on return file - will reflect");
                } else {
                    console.log("Read error:" + err.toString());
                }
            } else {
                // a file exists - but is empty?
                if ((data != null) && (data.length > 0)) {
                    // we have a file with content - lets process so it into a JSON
                    // object
                    if (Buffer.isBuffer(data)) {
                        // convert the buffer from hex to an ASCII string
                        body = data.toString('utf8');
                        console.log("test response:" + body);
                        responseBody = JSON.parse(body);
                    }
                }
            }

            // create an array with our values and then make it JSON with stringfy

            var output = JSON.stringify(responseBody);
            response.write(output);
            console.log("Returning:" + output);
            response.statusCode = 200;
            response.end();

        });

    } catch (err) {

        if (err.code === 'ENOENT') {
            console.log("on return file - will reflect");
        } else {
            console.log(err.toString());
        }
        var output = JSON.stringify(responseBody);
        response.write(output);
        console.log("Returning:" + output);
        response.statusCode = 200;
        response.end();
    }
}).listen(8080); // Activates this server, listening on port 8080.
