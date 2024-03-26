const { Level } = require('level')

// Create a database
const db = new Level('example', { valueEncoding: 'json' })

// Add an entry with key 'a' and value 1
db.put('a', 1)
    .then(() => {
        console.log('Entry added successfully');
    })
    .catch((error) => {
        console.error('Error adding entry:', error);
    });

const value = db.get('a')

console.log("value : ", value)