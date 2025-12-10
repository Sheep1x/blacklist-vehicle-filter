import sqlite3

# 连接到数据库
conn = sqlite3.connect('blacklist_vehicles.db')
cursor = conn.cursor()

# 查看users表的结构
print("Users table structure:")
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
for column in columns:
    print(column)

# 检查users表是否有role字段，如果没有则添加
column_names = [column[1] for column in columns]
if 'role' not in column_names:
    print("\nAdding role column to users table...")
    cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    conn.commit()
    print("Role column added successfully.")

# 确保admin用户的角色为admin
print("\nUpdating admin user role...")
cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
conn.commit()
print("Admin user role updated successfully.")

# 再次查看users表的结构
print("\nUpdated users table structure:")
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
for column in columns:
    print(column)

# 查看users表中的数据
print("\nUsers data:")
cursor.execute("SELECT * FROM users")
users = cursor.fetchall()
for user in users:
    print(user)

# 查看operation_logs表的结构
print("\nOperation_logs table structure:")
cursor.execute("PRAGMA table_info(operation_logs)")
columns = cursor.fetchall()
for column in columns:
    print(column)

# 关闭数据库连接
conn.close()