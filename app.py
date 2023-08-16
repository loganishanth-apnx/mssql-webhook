from flask import Flask, request, jsonify, render_template
import pyodbc
import time
import os

app = Flask(__name__)

# Database configuration
connection_string = os.environ['CONNECTION_STRING']

# Create a connection to the database
def create_connection():
    try:
        return pyodbc.connect(connection_string)
    except pyodbc.Error as e:
        print(f"Error connecting to the database: {str(e)}")
        return None

# Create the table
@app.route('/get_table_list', methods=['GET'])
def get_table_list():
    connection = create_connection()
    if connection:
        try:
            tables = connection.cursor().tables()
            table_list = [table.table_name for table in tables if table.table_type == 'TABLE']
            return jsonify(table_list), 200
        except pyodbc.Error as e:
            return jsonify({'message': f"Error fetching table list: {str(e)}"}), 500
        finally:
            connection.close()
    else:
        return jsonify({'message': 'Could not connect to the database.'}), 500
def create_table():
    connection = create_connection()
    if connection:
        try:
            with connection.cursor() as cursor:
                # Check if the table exists
                cursor.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'maintable';")
                table_exists = cursor.fetchone()[0]
                if not table_exists:
                    # Create the table
                    cursor.execute('''
                        CREATE TABLE maintable (
                            id INT PRIMARY KEY IDENTITY(1,1),
                            name VARCHAR(50) NOT NULL,
                            colour VARCHAR(100) NOT NULL
                        );
                    ''')
                    connection.commit()
                    print("Table created successfully.")
                else:
                    print("Table 'maintable' already exists. Skipping table creation.")
        except pyodbc.Error as e:
            print(f"Error creating table: {str(e)}")
        finally:
            connection.close()


# Endpoint to post data
@app.route('/post_data', methods=['POST'])
def post_data():
    data = request.form.to_dict()
    if not data:
        return jsonify({'message': 'No data provided.'}), 400

    connection = create_connection()
    if connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO maintable (name, colour) VALUES (?, ?)", data['name'], data['colour'])
                connection.commit()
                return jsonify({'message': 'Data posted successfully.'}), 200
        except pyodbc.Error as e:
            return jsonify({'message': f"Error inserting data: {str(e)}"}), 500
        finally:
            connection.close()
    else:
        return jsonify({'message': 'Could not connect to the database.'}), 500

# Endpoint to get data
@app.route('/get_data', methods=['GET'])
def get_data():
    connection = create_connection()
    if connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM maintable")
                data = cursor.fetchall()
                columns = [column[0] for column in cursor.description]
                result = []
                for row in data:
                    result.append(dict(zip(columns, row)))
                return jsonify(result), 200
        except pyodbc.Error as e:
            return jsonify({'message': f"Error fetching data: {str(e)}"}), 500
        finally:
            connection.close()
    else:
        return jsonify({'message': 'Could not connect to the database.'}), 500

@app.route('/delete_table', methods=['DELETE'])
def delete_table():
    if request.method == 'DELETE':
        table_name = request.form.get('table_name')
        if not table_name:
            return jsonify({'message': 'Table name is required.'}), 400

        connection = create_connection()
        if connection:
            try:
                with connection.cursor() as cursor:
                    # Check if the table exists
                    cursor.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = ?", table_name)
                    table_exists = cursor.fetchone()[0]
                    if table_exists:
                        # Delete the table
                        cursor.execute(f'DROP TABLE {table_name};')
                        connection.commit()
                        return jsonify({'message': f"Table '{table_name}' deleted successfully."}), 200
                    else:
                        return jsonify({'message': f"Table '{table_name}' does not exist."}), 404
            except pyodbc.Error as e:
                return jsonify({'message': f"Error deleting table: {str(e)}"}), 500
            finally:
                connection.close()
        else:
            return jsonify({'message': 'Could not connect to the database.'}), 500
    else:
        return jsonify({'message': 'Method not allowed.'}), 405



@app.route('/')
def index():
    return render_template('index.html')
if __name__ == '__main__':
    create_table()  # Call this to create the table before starting the application
    app.run(debug=True)



