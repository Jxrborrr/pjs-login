var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt')
const saltRounds = 10
var jwt = require('jsonwebtoken')
const secret = 'Pjs-loginn'
const auth = require('./authMiddleware')

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }));

const mysql = require('mysql2')

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'mydb',
})

function requireAdmin(req, res, next) {
  const email = req.user.email

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error(err)
        return res.status(500).json({ status: 'error', message: 'db error' })
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' })
      }

      const user = rows[0]
      if (!user.is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' })
      }

      req.admin = user
      next()
    }
  )
}


app.post('/register', jsonParser, function (req, res) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    if (err) {
      return res.json({ status: 'error', message: err })
    }

    connection.execute(
      'INSERT INTO users (email, password, fname, lname) VALUES (?, ?, ?, ?)',
      [req.body.email, hash, req.body.fname, req.body.lname],
      function (err) {
        if (err) {
          return res.json({ status: 'error', message: err })
        }
        res.json({ status: 'ok' })
      }
    )
  })
});

app.post('/login', jsonParser, function (req, res) {
  const { email, password } = req.body || {}
  if (!email || !password) {
    return res
      .status(400)
      .json({ status: 'error', message: 'email/password required' })
  }

  connection.execute(
    'SELECT * FROM users WHERE email = ? LIMIT 1',
    [email],
    function (err, users) {
      if (err) return res.json({ status: 'error', message: err })
      if (!users || users.length === 0) {
        return res.json({
          status: 'error',
          message: "The email address you entered isn't connected to an account.",
        })
      }

      const user = users[0]

      bcrypt.compare(password, user.password, function (err, isLogin) {
        if (err) return res.json({ status: 'error', message: err })

        if (!isLogin) {
          return res.json({
            status: 'error',
            message: "login The password that you've entered is incorrect.",
          })
        }

        const payload = {
          email: user.email,
          id: user.id,
          is_admin: !!user.is_admin,
        }

        const token = jwt.sign(payload, secret, { expiresIn: '12h' })

        res.json({
          status: 'ok',
          message: 'login success',
          token,
          user: {
            id: user.id,
            email: user.email,
            fname: user.fname,
            lname: user.lname,
            phone: user.phone,
            is_admin: !!user.is_admin,
          },
        })
      })
    }
  )
});

app.post('/authen', jsonParser, function (req, res) {
  try {
    const token = req.headers.authorization.split(' ')[1]
    var decoded = jwt.verify(token, secret)
    res.json({ status: 'ok', decoded })
  } catch (err) {
    res.json({ status: 'error', message: err.message })
  }
});

app.get('/me', auth, function (req, res) {
  const email = req.user.email

  connection.execute(
    'SELECT id, email, fname, lname, phone, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    function (err, results) {
      if (err) {
        return res.json({ status: 'error', message: err })
      }
      if (results.length === 0) {
        return res.json({ status: 'error', message: 'user not found' })
      }
      const user = results[0]
      res.json({
        status: 'ok',
        user: {
          id: user.id,
          email: user.email,
          fname: user.fname,
          lname: user.lname,
          phone: user.phone,
          is_admin: !!user.is_admin,
        },
      })
    }
  )
});

app.get("/rooms", (req, res) => {
  const sql = `
    SELECT 
      id,
      room_number AS name,
      room_type AS type,
      city,
      price_per_night AS pricePerNight,
      total_rooms,
      status
    FROM rooms
    WHERE status = 'available'
  `;

  connection.execute(sql, (err, rows) => {
    if (err) {
      console.error("ROOMS ERR:", err);
      return res.status(500).json({ status: "error", message: "db error" });
    }

    res.json({ status: "ok", rooms: rows });
  });
});

app.post("/bookings", auth, jsonParser, (req, res) => {
  const userId = req.user.id;
  const {
    roomId,
    roomName,
    city,
    roomType,      
    pricePerNight,
    rooms,
    nights,
    checkIn,
    checkOut,
    adults,
    children,
    totalPrice,
    booking_code
  } = req.body || {};

  if (!roomId || !checkIn || !checkOut || !totalPrice) {
    return res
      .status(400)
      .json({ status: "error", message: "missing required fields" });
  }

  connection.execute(
    "SELECT total_rooms FROM rooms WHERE id = ?",
    [roomId],
    (err, roomRows) => {
      if (err) {
        console.error("ROOM CHECK ERR:", err);
        return res
          .status(500)
          .json({ status: "error", message: "db error" });
      }

      if (!roomRows || roomRows.length === 0) {
        return res.json({ status: "error", message: "Room not found" });
      }

      const totalRooms = roomRows[0].total_rooms;

      connection.execute(
        `SELECT COUNT(*) AS booked
         FROM bookings
         WHERE room_id = ?
           AND status = 'confirmed'
           AND (
                (check_in <= ? AND check_out > ?) OR
                (check_in < ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
           )`,
        [roomId, checkOut, checkIn, checkOut, checkIn, checkIn, checkOut],
        (err2, result) => {
          if (err2) {
            console.error("BOOKED COUNT ERR:", err2);
            return res
              .status(500)
              .json({ status: "error", message: "db error" });
          }

          const booked = result[0].booked;

          if (booked >= totalRooms) {
            return res.json({
              status: "full",
              message: "This room is fully booked for the selected dates."
            });
          }

          const sql = `
            INSERT INTO bookings
              (user_id, room_id, room_name, city, room_type,
               price_per_night, rooms, nights,
               check_in, check_out,
               adults, children,
               total_price, booking_code, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `;

          connection.execute(
            sql,
            [
              userId,
              roomId,
              roomName,
              city,
              roomType,
              pricePerNight,
              rooms,
              nights,
              checkIn,
              checkOut,
              adults,
              children,
              totalPrice,
              booking_code,
              "confirmed"   
            ],
            (err3, result2) => {
              if (err3) {
                console.error("CREATE BOOKING ERR:", err3);
                return res
                  .status(500)
                  .json({ status: "error", message: "db error" });
              }

              res.json({
                status: "ok",
                bookingId: result2.insertId
              });
            }
          );
        }
      );
    }
  );
});

app.get('/my-bookings', auth, (req, res) => {
  const userId = req.user.id;

  const sql = `
    SELECT 
      b.*,
      r.room_number,
      r.room_type,
      r.city
    FROM bookings b
    LEFT JOIN rooms r ON b.room_id = r.id
    WHERE b.user_id = ?
    ORDER BY b.created_at DESC
  `;

  connection.execute(sql, [userId], (err, rows) => {
    if (err) {
      console.error('MY BOOKINGS ERR:', err);
      return res
        .status(500)
        .json({ status: 'error', message: 'db error' });
    }

    res.json({ status: 'ok', bookings: rows });
  });
});

app.post("/my-bookings", auth, (req, res) => {
  const {
    roomId,
    roomName,
    city,
    type,
    pricePerNight,
    rooms,
    nights,
    checkIn,
    checkOut,
    adults,
    children,
    totalPrice,
    booking_code
  } = req.body;

  connection.execute(
    "SELECT total_rooms FROM rooms WHERE id = ?",
    [roomId],
    (err, roomRows) => {
      if (err) return res.status(500).json({ status: "error", message: err });

      if (roomRows.length === 0)
        return res.json({ status: "error", message: "Room not found" });

      const totalRooms = roomRows[0].total_rooms;

      connection.execute(
        `SELECT COUNT(*) AS booked
         FROM bookings
         WHERE room_id = ?
           AND status = 'confirmed'
           AND (
                (check_in <= ? AND check_out > ?) OR
                (check_in < ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
           )`,
        [roomId, checkOut, checkIn, checkOut, checkIn, checkIn, checkOut],
        (err, result) => {
          if (err)
            return res.status(500).json({ status: "error", message: err });

          const booked = result[0].booked;

          if (booked >= totalRooms) {
            return res.json({
              status: "full",
              message: "This room is fully booked for the selected dates."
            });
          }

          connection.execute(
            `INSERT INTO bookings 
             (room_id, room_name, city, room_type, price_per_night, rooms, nights,
              check_in, check_out, adults, children, total_price, user_id, booking_code, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')`,
            [
              roomId,
              roomName,
              city,
              type,
              pricePerNight,
              rooms,
              nights,
              checkIn,
              checkOut,
              adults,
              children,
              totalPrice,
              req.user.id,
              booking_code
            ],
            (err) => {
              if (err)
                return res.status(500).json({ status: "error", message: err });

              res.json({ status: "ok", message: "Booking successful." });
            }
          );
        }
      );
    }
  );
});

app.delete('/my-bookings/:id', auth, (req, res) => {
  const bookingId = req.params.id;
  const userId = req.user.id;

  connection.execute(
    "DELETE FROM bookings WHERE id = ? AND user_id = ?",
    [bookingId, userId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ status: "error", message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ status: "error", message: "Booking not found" });
      }

      return res.json({ status: "ok", message: "Booking cancelled" });
    }
  );
});

app.get('/admin/rooms', auth, requireAdmin, (req, res) => {
  const email = req.user.email;

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error('ADMIN ROOMS USER ERR:', err);
        return res.status(500).json({ status: 'error', message: err.message });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' });
      }

      const user = rows[0];
      if (!user.is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' });
      }

      const sql = `
        SELECT 
          id,
          room_number,
          room_type,
          city,
          price_per_night       
        FROM rooms
        ORDER BY id ASC
      `;

      connection.execute(sql, [], (err2, rows2) => {
        if (err2) {
          console.error('ADMIN ROOMS DB ERR:', err2);
          return res.status(500).json({ status: 'error', message: err2.message });
        }
        res.json({ status: 'ok', rooms: rows2 });
      });
    }
  );
});

app.put("/admin/rooms/:id", jsonParser, (req, res) => {
  const { room_number, room_type, city, price_per_night, status } = req.body;
  const { id } = req.params;

  connection.execute(
    "UPDATE rooms SET room_number=?, room_type=?, city=?, price_per_night=?, status=? WHERE id=?",
    [room_number, room_type, city, price_per_night, status, id],
    (err, results) => {
      if (err) {
        console.log(err);
        if (err.code === "ER_DUP_ENTRY") {
          return res
            .status(400)
            .json({ status: "error", message: "Room number already exists" });
        }
        return res.status(500).json({ status: "error", message: "db error" });
      }
      res.json({ status: "ok" });
    }
  );
});

app.delete('/admin/rooms/:id', auth, requireAdmin, (req, res) => {
  const roomId = req.params.id;

  connection.execute(
    'DELETE FROM rooms WHERE id = ? LIMIT 1',
    [roomId],
    (err, result) => {
      if (err) {
        console.error("DELETE ROOM ERR:", err);
        return res.status(500).json({ status: "error", message: "db error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ status: "error", message: "room not found" });
      }

      return res.json({ status: "ok" });
    }
  );
});

app.post('/admin/rooms', auth, jsonParser, (req, res) => {
  const email = req.user.email;

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) return res.status(500).json({ status: 'error', message: err.message });
      if (!rows || rows.length === 0)
        return res.status(404).json({ status: 'error', message: 'user not found' });

      const user = rows[0];
      if (!user.is_admin)
        return res.status(403).json({ status: 'error', message: 'forbidden' });

      const { room_number, room_type, city, price_per_night, status } = req.body;

      const sql = `
        INSERT INTO rooms (room_number, room_type, city, price_per_night, status)
        VALUES (?, ?, ?, ?, ?)
      `;

      connection.execute(
        sql,
        [room_number, room_type, city, price_per_night, status],
        (err2, result) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ status: 'error', message: err2.message });
          }

          res.json({
            status: 'ok',
            message: 'Room saved',
            roomId: result.insertId,
          });
        }
      );
    }
  );
});

app.get('/admin/bookings', auth, (req, res) => {
  const email = req.user.email;

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ status: 'error', message: 'db error' });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' });
      }

      const user = rows[0];
      if (!user.is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' });
      }

      const sql = `
        SELECT 
          b.*,
          r.room_number, r.room_type, r.city,
          u.email AS user_email, u.fname, u.lname
        FROM bookings b
        LEFT JOIN rooms r ON b.room_id = r.id
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.created_at DESC
      `;

      connection.execute(sql, [], (err2, rows2) => {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ status: 'error', message: 'db error' });
        }
        res.json({ status: 'ok', bookings: rows2 });
      });
    }
  );
});

app.put('/admin/bookings/:id/status', auth, (req, res) => {
  const email = req.user.email;
  const bookingId = req.params.id;
  const { status } = req.body || {};

  if (!status) {
    return res.status(400).json({ status: 'error', message: 'status required' });
  }

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) return res.status(500).json({ status: 'error', message: 'db error' });

      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' });
      }

      if (!rows[0].is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' });
      }

      connection.execute(
        'UPDATE bookings SET status = ? WHERE id = ?',
        [status, bookingId],
        (err2) => {
          if (err2) {
            return res.status(500).json({ status: 'error', message: 'db error' });
          }

          return res.json({ status: 'ok' });
        }
      );
    }
  );
});

app.get('/admin/users', auth, (req, res) => {
  const email = req.user.email;

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error('ADMIN USERS CHECK ERR:', err);
        return res.status(500).json({ status: 'error', message: 'db error' });
      }

      if (!rows || rows.length === 0) {
        return res
          .status(404)
          .json({ status: 'error', message: 'user not found' });
      }

      const me = rows[0];
      if (!me.is_admin) {
        return res
          .status(403)
          .json({ status: 'error', message: 'forbidden (not admin)' });
      }
      const sql = `
        SELECT 
          id,
          email,
          fname,
          lname,
          phone,
          is_admin
        FROM users
        ORDER BY id ASC
      `;

      connection.execute(sql, [], (err2, users) => {
        if (err2) {
          console.error('ADMIN USERS LIST ERR:', err2);
          return res
            .status(500)
            .json({ status: 'error', message: err2.message || 'db error' });
        }

        res.json({ status: 'ok', users });
      });
    }
  );
});


app.put('/admin/users/:id', auth, jsonParser, (req, res) => {
  const email = req.user.email;
  const userId = parseInt(req.params.id, 10);

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ status: 'error', message: 'db error' });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' });
      }

      const me = rows[0];
      if (!me.is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' });
      }

      const { fname = null, lname = null, phone = null, is_admin = null } = req.body || {};

      const sql = `
        UPDATE users
        SET 
          fname = COALESCE(?, fname),
          lname = COALESCE(?, lname),
          phone = COALESCE(?, phone),
          is_admin = COALESCE(?, is_admin)
        WHERE id = ?
      `;

      connection.execute(
        sql,
        [fname, lname, phone, is_admin, userId],
        (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ status: 'error', message: 'db error' });
          }

          connection.execute(
            'SELECT id, email, fname, lname, phone, is_admin, created_at FROM users WHERE id = ? LIMIT 1',
            [userId],
            (err3, rows3) => {
              if (err3) {
                console.error(err3);
                return res.status(500).json({ status: 'error', message: 'db error' });
              }
              res.json({ status: 'ok', user: rows3[0] });
            }
          );
        }
      );
    }
  );
});

app.delete('/admin/users/:id', auth, (req, res) => {
  const email = req.user.email;
  const targetId = parseInt(req.params.id, 10);

  connection.execute(
    'SELECT id, is_admin FROM users WHERE email = ? LIMIT 1',
    [email],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ status: 'error', message: 'db error' });
      }
      if (!rows || rows.length === 0) {
        return res.status(404).json({ status: 'error', message: 'user not found' });
      }

      const me = rows[0];
      if (!me.is_admin) {
        return res.status(403).json({ status: 'error', message: 'forbidden' });
      }

      if (me.id === targetId) {
        return res.status(400).json({ status: 'error', message: 'cannot delete yourself' });
      }

      connection.execute(
        'DELETE FROM users WHERE id = ?',
        [targetId],
        (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ status: 'error', message: 'db error' });
          }
          res.json({ status: 'ok' });
        }
      );
    }
  );
});

app.listen(3333, function () {
  console.log('CORS-enabled web server listening on port 3333')
})
