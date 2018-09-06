import sqlite3
from datetime import tzinfo, timedelta, datetime, timezone
import time
import uuid
import json
import sys


class KGraph:
    mem_db = {}

    def __init__(self, db_path=None):
        if db_path is None:
            self.mem_db['connection'] = sqlite3.connect(':memory:')
        else:
            self.mem_db['connection'] = sqlite3.connect(db_path)
        self.mem_db['connection'].isolation_level = None

        sql = ' '.join(["CREATE TABLE IF NOT EXISTS relations",
                        "(uuid_src TEXT, rel_type TEXT, uuid_dst TEXT, dt_create INT)"])
        self.mem_db['connection'].execute(sql)

        sql = ' '.join(["CREATE TABLE IF NOT EXISTS objects",
                        "(uuid_obj TEXT, o_type TEXT, class_name TEXT, dt_create INT)"])
        self.mem_db['connection'].execute(sql)

        sql = ' '.join(["CREATE TABLE IF NOT EXISTS properties",
                        "(uuid TEXT, uuid_obj TEXT, key TEXT, value TEXT, v_type TEXT)"])
        self.mem_db['connection'].execute(sql)

    def __store_relation(self, uuid_src, uuid_dst, rel_type):
        epoch_time = int(time.time())
        sql = ' '.join(["INSERT INTO relations",
                                    "(uuid_src, uuid_dst, rel_type, dt_create)",
                             "VALUES (:uuid_src, :uuid_dst, :rel_type, :dt_create)"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_src":uuid_src,
                        "uuid_dst":uuid_dst,
                        "rel_type":rel_type,
                        "dt_create": epoch_time})
        return

    def store_relation(self, uuid_src, uuid_dst, rel_type):
        self.__store_relation(uuid_src, uuid_dst, rel_type)
        return

    def __store_object(self, o_type=None, class_name=None):
        u = str(uuid.uuid4())
        epoch_time = int(time.time())
        sql = ' '.join(["INSERT INTO objects",
                                    "(uuid_obj, o_type, class_name, dt_create)",
                             "VALUES (:uuid_obj, :o_type, :class_name, :dt_create)"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_obj":u,
                        "o_type":o_type,
                        "class_name":class_name,
                        "dt_create": epoch_time})
        return u

    def __store_property(self, uuid_obj, k, v, v_type):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO properties ",
                                    "(uuid, uuid_obj, key, value, v_type)",
                             "VALUES (:uuid, :uuid_obj, :key, :value, :v_type)"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid":u,
                        "uuid_obj":uuid_obj,
                        "key":k,
                        "value": v,
                        "v_type":v_type})
        return u

    def __store_int_key(self, uuid_obj, k, i):
        return self.__store_property(uuid_obj, k, i, 'int')

    def __store_int(self, uuid_obj, i):
        return self.__store_int_key(uuid_obj, '', i)

    def __store_str_key(self, uuid_obj, k, s):
        return self.__store_property(uuid_obj, k, s, 'str')

    def __store_str(self, uuid_obj, s):
        return self.__store_str_key(uuid_obj, '', s)

    def __store_json_key(self, uuid_obj, k, o):
        return self.__store_property(uuid_obj, k, json.JSONEncoder().encode(o), 'json')

    def __store_json(self, uuid_obj, o):
        return self.__store_json_key(uuid_obj, '', o)

    def store_int(self, i, class_name=None):
        u = self.__store_object("int", class_name)
        self.__store_int(u, i)
        return u

    def store_str(self, s, class_name=None):
        u = self.__store_object("str", class_name)
        self.__store_str(u, s)
        return u

    def store_dict(self, d, class_name=None):
        u = self.__store_object("dict", class_name)

        for k in d.keys():
            # what if the value is an int? => recurse
            if isinstance(d[k], str):
                self.__store_str_key(u, k, d[k])
            elif isinstance(d[k], int):
                self.__store_int_key(u, k, d[k])
            else:
                self.__store_json_key(u, k, d[k])
        return u

    def store_list(self, l, class_name=None):
        # Create and store object
        u = self.__store_object("list", class_name)

        # Store properties
        for i in l:
            # what if the value is an int? => recurse
            if isinstance(i, str):
                self.__store_str(u, i)
            elif isinstance(i, int):
                self.__store_int(u, i)
            else:
                self.__store_json(u, i)
        return u

    def store(self, obj, class_name=None):
        if isinstance(obj, dict):
            return self.store_dict(obj, class_name)
        elif isinstance(obj, list):
            return self.store_list(obj, class_name)
        elif isinstance(obj, str):
            return self.store_str(obj, class_name)
        elif isinstance(obj, int):
            return self.store_int(obj, class_name)

    def fetch_prop_by_obj_uuid(self, uuid_obj, o_type):
        if o_type == 'dict':
            r = {}
        elif o_type == 'list':
            r = []
        elif o_type == 'int':
            r = 0
        elif o_type == 'str':
            r = ''
        else:
            raise ValueError('Could not transform o_type %s by object uuid' % o_type)

        sql = ' '.join(["SELECT uuid, uuid_obj, key, value, v_type",
                          "FROM properties",
                         "WHERE uuid_obj = :uuid_obj"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_obj":uuid_obj})
        for (uuid, uuid_obj, key, value, v_type) in cursor:
            if o_type == 'int' and v_type == 'int':
                r = int(value)
            elif o_type == 'str' and v_type == 'str':
                r = value
            elif o_type == 'dict':
                if v_type == 'str':
                    r[key] = value
                elif v_type == 'int':
                    r[key] = int(value)
                elif v_type == 'json':
                    r[key] = json.loads(value)
                else:
                    raise ValueError('Could not transform v_type %s with key %s and object type %s' % 
                                     (v_type, key, o_type))
            elif o_type == 'list':
                if v_type == 'str':
                    r.append(value)
                elif v_type == 'int':
                    r.append(int(value))
                elif v_type == 'json':
                    r.append(json.loads(value))
                else:
                    raise ValueError('Could not transform v_type %s with key %s and object type %s' % 
                                     (v_type, key, o_type))
            else:
                raise ValueError('Could not transform v_type %s with key %s and object type %s' % 
                                 (v_type, key, o_type))
        return r

    def update_object_class_name(self, uuid_obj, class_name):
        sql = ' '.join(["UPDATE objects",
                           "SET class_name = :class_name",
                         "WHERE uuid_obj = :uuid_obj"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_obj":uuid_obj,
                        "class_name":class_name})
        return

    def fetch_object_rich(self, uuid_obj):
        sql = ' '.join(["SELECT uuid_obj, o_type, class_name, dt_create",
                          "FROM objects",
                         "WHERE uuid_obj = :uuid_obj"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_obj":uuid_obj})
        row = cursor.fetchone()
        if row is None:
            # No result is exit
            return None

        u           = row[0]
        o_type      = row[1]
        class_name  = row[2]
        dt_c        = row[3]

        o = {}
        o['uuid_obj'] = u
        o['o_type'] = o_type
        o['class_name'] = class_name
        o['dt_create'] = dt_c
        o['value'] = self.fetch_prop_by_obj_uuid(uuid_obj, o_type)

        return o

    def fetch_object(self, uuid_obj):
        sql = ' '.join(["SELECT uuid_obj, o_type, class_name, dt_create",
                          "FROM objects",
                         "WHERE uuid_obj = :uuid_obj"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                       {"uuid_obj":uuid_obj})
        row = cursor.fetchone()
        if row is None:
            # No result is exit
            return None

        u           = row[0]
        o_type      = row[1]
        class_name  = row[2]
        dt_c        = row[3]

        return self.fetch_prop_by_obj_uuid(uuid_obj, o_type)

    def get_properties(self, obj_uuid):
        sql = ' '.join(["select *",
                          "from relations",
                         "where uuid_src = :u_src",
                            "or uuid_dst = :u_dst"])
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql,
                                        {"u_src":obj_uuid,
                                         "u_dst":obj_uuid})
        for (uuid_src, uuid_dst, rel_type, dt_create) in cursor:
            # relations to objects, two sides, are fetched
            t = datetime.fromtimestamp(dt_create, timezone.utc)
            t1 = datetime.astimezone(t)
            print(uuid_src, uuid_dst, rel_type, dt_create, t, t1)


    def enum_objects_list_rich(self, class_name=None):
        l = []
        sq = []
        para = {}

        sq.append("SELECT uuid_obj, o_type, class_name, dt_create")
        sq.append("FROM objects")
        if class_name is not None:
            sq.append("WHERE class_name = :class_name")
            para['class_name'] = class_name

        sql = ' '.join(sq)

        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql, para)
        for (uuid_obj, o_type, class_name, dt_create) in cursor:
            r = {}
            r['uuid'] = uuid_obj
            r['o_type'] = o_type
            r['class_name'] = class_name
            r['dt_create'] = dt_create
            r['value'] = self.fetch_prop_by_obj_uuid(uuid_obj, o_type)
            l.append(r)
        return l

    def enum_objects_list(self, class_name=None):
        l = []
        sq = []
        para = {}

        sq.append("SELECT uuid_obj, o_type")
        sq.append("FROM objects")
        if class_name is not None:
            sq.append("WHERE class_name = :class_name")
            para['class_name'] = class_name

        sql = ' '.join(sq)

        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql, para)
        for (uuid_obj, o_type) in cursor:
            r = self.fetch_prop_by_obj_uuid(uuid_obj, o_type)
            l.append(r)
        return l

    def count_objects_list(self, class_name=None):
        l = []
        sq = []
        para = {}

        sq.append("SELECT count(uuid_obj)")
        sq.append("FROM objects")
        if class_name is not None:
            sq.append("WHERE class_name = :class_name")
            para['class_name'] = class_name

        sql = ' '.join(sq)

        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql, para)
        return cursor.fetchone()[0]

    def search_objects(self, **kwargs):
        options = ['rich',
                   'count',
                   'or_class_name',
                   'and_class_name',
                   'or_key',
                   'and_key',
                   'or_value',
                   'and_value']

        para = {}

        for k, v in kwargs.items():
            if k not in options:
                raise ValueError('search_objects does not accept %s as input key' % k)
            else:
                para[k] = v

        sq = []
        sq.append("SELECT")
        if 'count' in para:
            sq.append("count(objects.uuid_obj)")
        else:
            sq.append("objects.uuid_obj")

#        sq.append("objects.o_type,")
#        sq.append("objects.class_name,")
#        sq.append("objects.dt_create,")
#
#        sq.append("properties.uuid,")
#        sq.append("properties.uuid_obj")
#        sq.append("properties.key,")
#        sq.append("properties.value,")
#        sq.append("properties.v_type")

        sq.append("FROM objects, properties")
        sq.append("WHERE")
        sq.append("properties.uuid_obj == objects.uuid_obj")

        if 'and_class_name' in para:
            sq.append("AND")
            sq.append("objects.class_name = :and_class_name")
        elif 'or_class_name' in para:
            sq.append("OR")
            sq.append("objects.class_name = :or_class_name")

        if 'and_key' in para:
            sq.append("AND")
            sq.append("properties.key = :and_key")
        elif 'or_key' in para:
            sq.append("OR")
            sq.append("properties.key = :or_key")

        if 'and_value' in para:
            sq.append("AND")
            sq.append("properties.value = :and_value")
        elif 'or_value' in para:
            sq.append("OR")
            sq.append("properties.value = :or_value")

        sq.append('GROUP BY objects.uuid_obj')

        sql = ' '.join(sq)
        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql, para)
        if 'count' in para:
            return cursor.fetchone()[0]
        else:
            l = []

            if 'rich' in para:
                for (uuid_obj,) in cursor:
                    r = self.fetch_object_rich(uuid_obj)
                    l.append(r)
            else:
                for (uuid_obj,) in cursor:
                    r = self.fetch_object(uuid_obj)
                    l.append(r)
            return l

    def search_object_by_property(self, rich=False, key=None, value=None):
        l = []

        sq = []
        para = {}

        sq.append("SELECT uuid_obj")
        sq.append("FROM properties")
        sq.append("WHERE key = :key")
        sq.append("OR value = :value")
        sq.append("GROUP BY uuid_obj")

        para['key'] = key
        para['value'] = value

        sql = ' '.join(sq)

        cursor = self.mem_db['connection'].cursor()
        cursor.execute(sql, para)
        if rich:
            for (uuid_obj) in cursor:
                r = self.fetch_object_rich(uuid_obj)
                l.append(r)
        else:
            for (uuid_obj) in cursor:
                r = self.fetch_object(uuid_obj)
                l.append(r)
        return l


    def test(self):
        cursor = self.mem_db['connection'].cursor()

        sql = ' '.join(["SELECT *",
                          "FROM properties"])
        cursor.execute(sql)
        for (uuid, uuid_obj, key, value, v_type) in cursor:
            print(uuid, uuid_obj, key, value, v_type)

        sql = ' '.join(["SELECT *",
                          "FROM objects"])
        cursor.execute(sql)
        for (uuid_obj, o_type, class_name, dt_create) in cursor:
            t = datetime.fromtimestamp(dt_create, timezone.utc)
            t1 = datetime.astimezone(t)
            print(uuid_obj, o_type, dt_create, t, t1)

        sql = ' '.join(["SELECT *",
                          "FROM relations"])
        cursor.execute(sql)
        for (uuid_src, uuid_dst, rel_type, dt_create) in cursor:
            t = datetime.fromtimestamp(dt_create, timezone.utc)
            t1 = datetime.astimezone(t)
            print(uuid_src, uuid_dst, rel_type, dt_create, t, t1)

        sql = ' '.join(["SELECT *",
                          "FROM objects, relations, properties",
                        "WHERE relations.rel_type = :rel_type"])
        cursor.execute(sql,
                                      {"rel_type":"str"})
        res = cursor.fetchall()
        for row in res:
            print(row)


#select objects.uuid_obj, objects.o_type, objects.class_name, objects.dt_create, properties.uuid, properties.uuid_obj, properties.key, properties.value, properties.v_type  from objects, properties WHERE properties.uuid_obj == objects.uuid_obj order by objects.uuid_obj;

def test_verify_KGraph():
    kg = KGraph('test.db')

    i = 11
    u1 = kg.store(i)

    s = "foo_str"
    u2 = kg.store(s)

    t1 = {}
    t1['foo'] = 42
    t1['foo2'] = 'bar2'
    u3 = kg.store(t1)

    t2 = {}
    t2['foo'] = 'bar'
    t2['foo2'] = 'bar2'
    u4 = kg.store(t2)

    l = []
    l.append("list_foo")
    l.append("list_foo1")
    u5 = kg.store(l)

    l.append(t1)
    u6 = kg.store(l)

    t1['complex'] = t2
    u7 = kg.store(t1)

    kg.test()

    print(u1)
    print(kg.fetch_object(u1))

    print(u2)
    print(kg.fetch_object(u2))

    print(u3)
    print(kg.fetch_object(u3))

    print(u4)
    print(kg.fetch_object(u4))

    print(u5)
    print(kg.fetch_object(u5))

    print(u6)
    print(kg.fetch_object(u6))

    print(u7)
    print(kg.fetch_object(u7))

    print(kg.enum_objects_list())

    print(kg.enum_objects_list_rich())


if __name__ == "__main__":
    test_verify_KGraph()

#################
# t = datetime.fromtimestamp(dt_create, timezone.utc)
# t1 = datetime.astimezone(t)
#print(uuid, o_type, dt_create, t, t1)
