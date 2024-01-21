import csv
import sqlite3
import time

def read_csv_and_insert(file_path, db_path):
    max_retries = 5  # Maximum number of retries
    retry_delay = 1  # Delay between retries in seconds

    for retry_count in range(max_retries):
        try:
            with sqlite3.connect(db_path) as connection:
                cursor = connection.cursor()

                with open(file_path, 'r', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)

                    for row in reader:
                        values = (
                            row['id'],
                            row['name'],
                            row['endpointName'],
                            row['startingPrice'],
                            row['description'],
                            row['imagePath'],
                            row['state'],
                            row['winner'],
                            row['category'],
                            row['openClose'],
                            row['maxLimit'],
                            row['status'],
                            row['image2'],
                            row['image3'],
                            row['image4'],
                            row['image5']
                        )
                        cursor.execute('''
                            INSERT INTO products (id, name, endpointName, startingPrice, desc, imagePath, state, winner, category, openClose, maxLimit, status, image2, image3, image4, image5)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', values)

            print("Data inserted successfully.")
            break  # Break out of the retry loop on successful insertion

        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                print(f"Database is locked. Retrying ({retry_count + 1}/{max_retries})...")
                time.sleep(retry_delay)
            else:
                print(f"An error occurred: {e}")
                break  # Break out of the retry loop on other errors

        except Exception as e:
            print(f"An error occurred: {e}")
            break  # Break out of the retry loop on other errors

# Example usage
csv_file_path = 'products_rows.csv'  # Replace with your CSV file path
db_file_path = 'products.db'  # Replace with your SQLite database file path
read_csv_and_insert(csv_file_path, db_file_path)
