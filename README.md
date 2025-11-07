# JWT Authorization Matrix

A Burp Suite extension for testing JWT (JSON Web Token) based authorization in web applications. This extension creates a matrix view of endpoints vs users, helping pentesters identify authorization issues across different user roles.

## Features

- Creates a visual matrix of endpoint access patterns
- Captures and organizes requests with JWT tokens
- Supports JWT tokens in both Authorization headers and Cookies
- Color-coded response status codes for quick analysis
- Detailed request/response inspection for each matrix cell
- Replay functionality to test endpoints with different JWT tokens
- JWT token management table for tracking valid tokens
- Proxy history parsing for retrospective analysis
- Configurable JWT claim field for user identification
- Request grouping by endpoint patterns

## Installation

1. Download and install [Jython Standalone JAR](https://www.jython.org/download.html)
2. In Burp Suite, go to `Extender` -> `Options`
3. Under "Python Environment", set the location of your Jython standalone JAR
4. Go to `Extender` -> `Extensions`
5. Click "Add", select "Python" as the extension type
6. Select the `JWTAuthMatrix.py` file
7. Click "Next" to load the extension

## Usage

### Configuration

1. Go to the "Configuration" tab in the JWT Authorization Matrix
2. Set the JWT claim field used to identify users (default: "sub")
3. Choose JWT token location (Authorization header or Cookie)
4. Configure which Burp tools to monitor (Proxy, Repeater, Intruder)

### Building the Matrix

The matrix can be populated in two ways:
1. **Automatic Capture**: Browse the application while the extension is running
2. **Parse Proxy History**: Click "Parse Proxy History" to analyze existing Burp traffic

### Matrix Features

- Click cells to view detailed requests and responses
- Use [+] to expand grouped endpoints with parameters
- Right-click endpoints to remove them from the matrix
- Filter endpoints using the search box

### JWT Management

- Track valid JWT tokens for different users
- Replay captured requests with different tokens
- Test authorization across user roles

### Replay Testing

1. Add JWT tokens to the JWT Management table
2. Select requests to replay
3. Click "Replay All Requests with JWT Tokens"
4. View results in the Replay Matrix tab

## Development

This extension is written in Python (Jython) and uses Burp's Extender API.

### Requirements

- Burp Suite Professional
- Jython Standalone 2.7.x
- Java Runtime Environment

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Author

Alexis Pain

(This code is a mess because it's written by Claude AI and debugged by me....)