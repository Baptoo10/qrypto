const { Level } = require('level')

async function main() {
    // Create a database
    const db = new Level('dbtest', { valueEncoding: 'json' })

    try {
        // Add an entry with key 'a' and value 1
        await db.put('a', 1);
        await db.put('b', 2);
        await db.put('c', 3);
        console.log('Entry added successfully');

        // Synchronize the data to disk
        await db.close();
        await db.open();

        // Get the value associated to the key
        const valuea = await db.get('a');
        const valueb = await db.get('b');
        const valuec = await db.get('c');
        
        console.log("Value for key 'a':", valuea);
        console.log("Value for key 'b':", valueb);
        console.log("Value for key 'c':", valuec);
    } catch (error) {
        console.error('Error:', error);
    }
}

main().catch(console.error);


//usage : leveldbutil dump ./example/000005.ldb
