import pyshark
import socket
import sqlite3 as sq
from datetime import datetime

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

#Записываем в базу пришедший пакет
def addPackage(streamId, direction, packageSize):
    res = cur.execute("SELECT packageCount FROM packageData WHERE streamId = ? AND direction = ? AND packageSize = ?", [streamId, direction, packageSize]).fetchone()
    
    if (res == None):
        cur.execute("INSERT INTO packageData VALUES(?,?,?,1)", [streamId, direction, packageSize])
    else:
        cur.execute("UPDATE packageData SET packageCount = packageCount + 1 WHERE streamId = ? AND direction = ? AND packageSize = ?", [streamId, direction, packageSize])

#Записываем в базу зашифрованную полезную нагрузку        
def addEncPayload(streamId, direction, encPayload):
    res = cur.execute("SELECT packageCount FROM encPayloadData WHERE streamId = ? AND direction = ? AND encPayload = ?", [streamId, direction, encPayload]).fetchone()
    
    if(res == None):
        cur.execute("INSERT INTO encPayloadData VALUES(?,?,?,1)", [streamId, direction, encPayload])
    else:
        cur.execute("UPDATE encPayloadData SET packageCount = packageCount + 1 WHERE streamId = ? AND direction = ? AND encPayload = ?", [streamId, direction, encPayload])
        
#Инициализация нового потока
def addNewStream(source, destination, sourcePort, destinationPort, protocol, streamIndex, packageSize, encPayload, direction):
    curTime = datetime.now()
    cur.execute("INSERT INTO streamInfo(id, source, destination, sourcePort, destinationPort, protocol, streamIndex, "
                + "packageCount, lastArrivalTime, packageSizeMax, packageSizeRMS, packageSizeAvg, "
                + direction + "PackageCount, " + direction + "LastArrivalTime, " + direction + "PackageSizeMax, " + direction + "PackageSizeRMS, " + direction + "PackageSizeAvg, "
                + "encPayloadMax, encPayloadRMS, encPayloadAvg, " + direction + "EncPayloadMax, " + direction + "EncPayloadRMS, " + direction + "EncPayloadAvg) "
                + "VALUES(NULL, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [source, destination, sourcePort, destinationPort, protocol, streamIndex, curTime, packageSize, packageSize, packageSize, curTime, packageSize, packageSize, packageSize, 
                 encPayload, encPayload, encPayload, encPayload, encPayload, encPayload])
        
#Считаем признаки связанные с размерами пакетов
def getPackageSizeFeatures(streamId, direction, packageCount):
    if(direction == "mixed"):
        cur.execute("SELECT packageSize, packageCount FROM packageData WHERE streamId = ? ORDER BY packageSize ASC", [streamId])
    else:
        cur.execute("SELECT packageSize, packageCount FROM packageData WHERE streamId = ? AND direction = ? ORDER BY packageSize ASC", [streamId, direction])
        
    #Матожидание величины
    M_x = 0
    #Матожидание квадрата величины
    M_x2 = 0
    
    range25 = int(packageCount * 0.25)
    range50 = int(packageCount * 0.5)
    range75 = int(packageCount * 0.75)
    
    features = [0, 0, 0, 0, 0, 0]
        
    for res in cur:
        M_x += res[0] * res[1]
        M_x2 += (res[0] ** 2) * res[1]
        
        if(res[1] < range25):
            features[3] += res[0] * res[1]
            range25 -= res[1]
        else:
            features[3] += res[0] * range25
            range25 = 0
            
        if(res[1] < range50):
            features[4] += res[0] * res[1]
            range50 -= res[1]
        else:
            features[4] += res[0] * range50
            range50 = 0
            
        if(res[1] < range75):
            features[5] += res[0] * res[1]
            range75 -= res[1]
        else:
            features[5] += res[0] * range75
            range75 = 0
    
    M_x /= packageCount
    M_x2 /= packageCount
    
    features[0] = M_x2 - (M_x ** 2)   # Variance
    features[1] = M_x2 ** 0.5         # RMS
    features[2] = M_x                 # Avg
    
    return features

#Считаем признаки связанные с зашифрованной полезной нагрузкой пакетов
def getEncPayloadFeatures(streamId, direction, packageCount):
    if(direction == "mixed"):
        cur.execute("SELECT encPayload, packageCount FROM encPayloadData WHERE streamId = ? ORDER BY encPayload ASC", [streamId])
    else:
        cur.execute("SELECT encPayload, packageCount FROM encPayloadData WHERE streamId = ? AND direction = ? ORDER BY encPayload ASC", [streamId, direction])
        
    #Матожидание величины
    M_x = 0
    #Матожидание квадрата величины
    M_x2 = 0
    
    range25 = int(packageCount * 0.25)
    range50 = int(packageCount * 0.5)
    range75 = int(packageCount * 0.75)
    
    features = [0, 0, 0, 0, 0, 0]
        
    for res in cur:
        M_x += res[0] * res[1]
        M_x2 += (res[0] ** 2) * res[1]
        
        if(res[1] < range25):
            features[3] += res[0] * res[1]
            range25 -= res[1]
        else:
            features[3] += res[0] * range25
            range25 = 0
            
        if(res[1] < range50):
            features[4] += res[0] * res[1]
            range50 -= res[1]
        else:
            features[4] += res[0] * range50
            range50 = 0
            
        if(res[1] < range75):
            features[5] += res[0] * res[1]
            range75 -= res[1]
        else:
            features[5] += res[0] * range75
            range75 = 0
    
    M_x /= packageCount
    M_x2 /= packageCount
    
    features[0] = M_x2 - (M_x ** 2)   # Variance
    features[1] = M_x2 ** 0.5         # RMS
    features[2] = M_x                 # Avg
    
    return features

#Считаем признаки связанные со временем между прибытием пакетов
def getDeltaTimeFeatures(streamId, direction, packageCount):
    cur.execute("SELECT deltaTime FROM packageDeltaTime WHERE streamId = ? AND direction = ? ORDER BY deltaTime ASC", [streamId, direction])
    
    data = []
    for res in cur:
        data.append(res[0])
    
    range25 = int((packageCount - 1) * 0.25)
    range50 = int((packageCount - 1) * 0.5)
    range75 = int((packageCount - 1) * 0.75)
    
    features = [0, 0, 0, 0]
    features[0] = sum(data[0:range25])
    features[1] = features[0] + sum(data[range25:range50])
    features[2] = features[1] + sum(data[range50:range75])
    features[3] = (features[2] + sum(data[range75:packageCount])) / (packageCount - 1)
    
    return features

#Обновление признаков связанных со временем между прибытием пакетов
def updateDeltaTimeFeatures(streamId, direction, curTime, lastArrivalTime, deltaTimeMax, packageCount):
    if(lastArrivalTime == None): return
    
    deltaTime = curTime - lastArrivalTime
    cur.execute("INSERT INTO packageDeltaTime VALUES(?,?,?)", [streamId, direction, deltaTime.total_seconds()])
    
    deltaTimeFeatures = getDeltaTimeFeatures(streamId, direction, packageCount)
    deltaTimeFeatures.append(streamId)
    
    if(direction == "mixed"):
        direction = ""
    
    if(deltaTime.total_seconds() > deltaTimeMax):
        cur.execute("UPDATE streamInfo SET " + direction + "DeltaTimeMax = ? WHERE id = ?", [deltaTime.total_seconds(), streamId])
    
    cur.execute("UPDATE streamInfo SET " + direction + "DeltaTimeSum25 = ?, " + direction + "DeltaTimeSum50 = ?, " + direction + "DeltaTimeSum75 = ?, "
                + direction + "DeltaTimeAvg = ? WHERE id = ?", deltaTimeFeatures)

#Получить id потока по определяющим его полям. Если такого потока нет то функция вернет NONE
def getStreamId(source, destination, sourcePort, destinationPort, protocol, streamIndex):
    cur.execute("SELECT id FROM streamInfo WHERE source = ? AND destination = ? AND sourcePort = ? AND destinationPort = ? AND protocol = ? AND streamIndex = ?", 
                [source, destination, sourcePort, destinationPort, protocol, streamIndex])
    
    for res in cur:
        return res[0]
    
#Обработка приходящего извне пакета, обновление признаков соответствующего потока либо создание записи о новом потоке
def handlePackage(source, destination, sourcePort, destinationPort, protocol, streamIndex, packageSize, encPayload, direction):
    print(source + " " + destination + " " + str(sourcePort) + " " + str(destinationPort) + " " + protocol + " " + str(streamIndex) + " " + str(packageSize) + " " + str(encPayload) + " " + direction)
    if(direction == "serverClient"):
        source, destination = destination, source
        sourcePort, destinationPort = destinationPort, sourcePort
        
    _id = getStreamId(source, destination, sourcePort, destinationPort, protocol, streamIndex)
    
    #Если такого потока не существует
    if(_id == None):
        addNewStream(source, destination, sourcePort, destinationPort, protocol, streamIndex, packageSize, encPayload, direction)
            
        _id = getStreamId(source, destination, sourcePort, destinationPort, protocol, streamIndex)
        addPackage(_id, direction, packageSize)
        addEncPayload(_id, direction, encPayload)
    else:
        curTime = datetime.now() #Будет на вход приходить
        streamData = cur.execute("SELECT lastArrivalTime, packageCount, packageSizeMax, encPayloadMax, deltaTimeMax, " 
                                 + direction + "LastArrivalTime, " + direction + "PackageCount, " + direction + "PackageSizeMax, " 
                                 + direction + "EncPayloadMax, " + direction + "DeltaTimeMax FROM streamInfo WHERE id = ?", [_id]).fetchall()[0]
        
        lastArrivalTime, packageCount, packageSizeMax, encPayloadMax, deltaTimeMax, curDirLastArrivalTime, curDirPackageCount, curDirPackageSizeMax, curDirEncPayloadMax, curDirDeltaTimeMax = streamData
        packageCount += 1
        curDirPackageCount += 1
        
        cur.execute("UPDATE streamInfo SET packageCount = ?, lastArrivalTime = ?, " + direction + "PackageCount = ?, " + direction + "LastArrivalTime = ? WHERE id = ?",
                    [packageCount, curTime, curDirPackageCount, curTime, _id])
        
        updateDeltaTimeFeatures(_id, direction, curTime, curDirLastArrivalTime, curDirDeltaTimeMax, curDirPackageCount)
        updateDeltaTimeFeatures(_id, "mixed", curTime, lastArrivalTime, deltaTimeMax, packageCount)
        
        addPackage(_id, direction, packageSize)
        addEncPayload(_id, direction, encPayload)
        
        if(packageSize > packageSizeMax):
            cur.execute("UPDATE streamInfo SET packageSizeMax = ?, " + direction + "PackageSizeMax = ? WHERE id = ?", [packageSize, packageSize, _id])
        elif(packageSize > curDirPackageSizeMax):
            cur.execute("UPDATE streamInfo SET " + direction + "PackageSizeMax = ? WHERE id = ?", [packageSize, _id])
            
        if(encPayload > encPayloadMax):
            cur.execute("UPDATE streamInfo SET encPayloadMax = ?, " + direction + "EncPayloadMax = ? WHERE id = ?", [encPayload, encPayload, _id])
        elif(encPayload > curDirEncPayloadMax):
            cur.execute("UPDATE streamInfo SET " + direction + "EncPayloadMax = ? WHERE id = ?", [encPayload, _id])
        
        packageSizeFeatures = getPackageSizeFeatures(_id, "mixed", packageCount) + getPackageSizeFeatures(_id, direction, curDirPackageCount)
        packageSizeFeatures.append(_id)
        
        encPayloadFeatures = getEncPayloadFeatures(_id, "mixed", packageCount) + getEncPayloadFeatures(_id, direction, curDirPackageCount)
        encPayloadFeatures.append(_id)
        
        cur.execute("UPDATE streamInfo SET packageSizeVariance = ?, packageSizeRMS = ?, packageSizeAvg = ?, packageSizeSum25 = ?, packageSizeSum50 = ?, packageSizeSum75 = ?, "
                    + direction + "PackageSizeVariance = ?, " + direction + "PackageSizeRMS = ?, " + direction + "PackageSizeAvg = ?, "
                    + direction + "PackageSizeSum25 = ?, " + direction + "PackageSizeSum50 = ?, " + direction + "PackageSizeSum75 = ? WHERE id = ?",
                    packageSizeFeatures)
        
        cur.execute("UPDATE streamInfo SET encPayloadVariance = ?, encPayloadRMS = ?, encPayloadAvg = ?, encPayloadSum25 = ?, encPayloadSum50 = ?, encPayloadSum75 = ?, "
                    + direction + "EncPayloadVariance = ?, " + direction + "EncPayloadRMS = ?, " + direction + "EncPayloadAvg = ?, "
                    + direction + "EncPayloadSum25 = ?, " + direction + "EncPayloadSum50 = ?, " + direction + "EncPayloadSum75 = ? WHERE id = ?",
                    encPayloadFeatures)

with sq.connect("database.db", detect_types=sq.PARSE_DECLTYPES | sq.PARSE_COLNAMES) as con:
    cur = con.cursor()
    
    cur.execute("DROP TABLE IF EXISTS streamInfo")
    cur.execute("DROP TABLE IF EXISTS packageData")
    cur.execute("DROP TABLE IF EXISTS encPayloadData")
    cur.execute("DROP TABLE IF EXISTS packageDeltaTime")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS streamInfo (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        destination TEXT NOT NULL,
        sourcePort INTEGER NOT NULL,
        destinationPort INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'TCP',
        streamIndex INTEGER NOT NULL,
        packageCount INTEGER,
        lastArrivalTime timestamp,
        packageSizeMax INTEGER,
        packageSizeVariance REAL DEFAULT 0,
        packageSizeRMS REAL,
        packageSizeAvg REAL,
        packageSizeSum25 INTEGER DEFAULT 0,
        packageSizeSum50 INTEGER DEFAULT 0,
        packageSizeSum75 INTEGER DEFAULT 0,
        deltaTimeMax REAL DEFAULT 0,
        deltaTimeAvg REAL DEFAULT 0,
        deltaTimeSum25 REAL DEFAULT 0,
        deltaTimeSum50 REAL DEFAULT 0,
        deltaTimeSum75 REAL DEFAULT 0,
        encPayloadMax INTEGER DEFAULT 0,
        encPayloadVariance REAL DEFAULT 0,
        encPayloadRMS REAL,
        encPayloadAvg REAL,
        encPayloadSum25 INTEGER DEFAULT 0,
        encPayloadSum50 INTEGER DEFAULT 0,
        encPayloadSum75 INTEGER DEFAULT 0,
        clientServerPackageCount INTEGER DEFAULT 0,
        clientServerLastArrivalTime timestamp,
        clientServerPackageSizeMax INTEGER DEFAULT 0,
        clientServerPackageSizeVariance REAL DEFAULT 0,
        clientServerPackageSizeRMS REAL DEFAULT 0,
        clientServerPackageSizeAvg REAL DEFAULT 0,
        clientServerPackageSizeSum25 INTEGER DEFAULT 0,
        clientServerPackageSizeSum50 INTEGER DEFAULT 0,
        clientServerPackageSizeSum75 INTEGER DEFAULT 0,
        clientServerDeltaTimeMax REAL DEFAULT 0,
        clientServerDeltaTimeAvg REAL DEFAULT 0,
        clientServerDeltaTimeSum25 REAL DEFAULT 0,
        clientServerDeltaTimeSum50 REAL DEFAULT 0,
        clientServerDeltaTimeSum75 REAL DEFAULT 0,
        clientServerEncPayloadMax INTEGER DEFAULT 0,
        clientServerEncPayloadVariance REAL DEFAULT 0,
        clientServerEncPayloadRMS REAL DEFAULT 0,
        clientServerEncPayloadAvg REAL DEFAULT 0,
        clientServerEncPayloadSum25 INTEGER DEFAULT 0,
        clientServerEncPayloadSum50 INTEGER DEFAULT 0,
        clientServerEncPayloadSum75 INTEGER DEFAULT 0,
        serverClientPackageCount INTEGER DEFAULT 0,
        serverClientLastArrivalTime timestamp,
        serverClientPackageSizeMax INTEGER DEFAULT 0,
        serverClientPackageSizeVariance REAL DEFAULT 0,
        serverClientPackageSizeRMS REAL DEFAULT 0,
        serverClientPackageSizeAvg REAL DEFAULT 0,
        serverClientPackageSizeSum25 INTEGER DEFAULT 0,
        serverClientPackageSizeSum50 INTEGER DEFAULT 0,
        serverClientPackageSizeSum75 INTEGER DEFAULT 0,
        serverClientDeltaTimeMax REAL DEFAULT 0,
        serverClientDeltaTimeAvg REAL DEFAULT 0,
        serverClientDeltaTimeSum25 REAL DEFAULT 0,
        serverClientDeltaTimeSum50 REAL DEFAULT 0,
        serverClientDeltaTimeSum75 REAL DEFAULT 0,
        serverClientEncPayloadMax INTEGER DEFAULT 0,
        serverClientEncPayloadVariance REAL DEFAULT 0,
        serverClientEncPayloadRMS REAL DEFAULT 0,
        serverClientEncPayloadAvg REAL DEFAULT 0,
        serverClientEncPayloadSum25 INTEGER DEFAULT 0,
        serverClientEncPayloadSum50 INTEGER DEFAULT 0,
        serverClientEncPayloadSum75 INTEGER DEFAULT 0,
        
        UNIQUE(source, destination, sourcePort, destinationPort, protocol, streamIndex)
        )""")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packageDeltaTime (
        streamId INTEGER NOT NULL,
        direction TEXT NOT NULL,
        deltaTime REAL NOT NULL,
        FOREIGN KEY(streamId) REFERENCES streamInfo(id)
        )""")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packageData (
        streamId INTEGER NOT NULL,
        direction TEXT NOT NULL,
        packageSize INTEGER NOT NULL,
        packageCount INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY(streamId, direction, packageSize),
        FOREIGN KEY(streamId) REFERENCES streamInfo(id)
        )""")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS encPayloadData (
        streamId INTEGER NOT NULL,
        direction TEXT NOT NULL,
        encPayload INTEGER NOT NULL,
        packageCount INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY(streamId, direction, encPayload),
        FOREIGN KEY(streamId) REFERENCES streamInfo(id)
        )""")

    #handlePackage("192.168.1.17", "87.240.129.132", 59382, 443, "TCP", 0, 106, 66, "clientServer")


    pcap_reader = pyshark.LiveCapture()
    for packet in pcap_reader.sniff_continuously():
        if("eth" in packet and "ip" in packet and "tcp" in packet):
            source = str(packet.ip.src)
            destination = str(packet.ip.dst)
            sourcePort = int(packet.tcp.srcport)
            destinationPort = int(packet.tcp.dstport)
            protocol = str(packet.transport_layer)
            streamIndex = int(packet.tcp.stream)
            packageSize = int(packet.ip.len)
            encPayload = int(packet.tcp.len)
            if(source == get_local_ip()):
                direction = "clientServer"
            else:
                direction = "serverClient"
            
            handlePackage(source, destination, sourcePort, destinationPort, protocol, streamIndex, packageSize, encPayload, direction)
            cur.execute("COMMIT;")