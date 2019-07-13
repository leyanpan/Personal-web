---
title: SQL Injection Problem on CTF learn
---

__Warning: This blog contains all spoilers to the ['INJ3CTION TIME'](https://ctflearn.com/problems/149) problem on CTF learn. If you want to do it yourself please don't read this blog yet.__

# Introduction
So I was still half way solving the Google CTF Reverse Engineering problem in my first blog when I finally got tired and decided to do something less time-consuming. As we all know, SQL injection is one of the most basic (and important) ability a security analyst must master. Therefore, I chose this ['INJ3CTION TIME'](https://ctflearn.com/problems/149) problem labeled as 'Hard' here as a platform to learn the basics of SQL injection.

# Basic attempts

Following this link I went to a very basic website which allows you to enter the ID of an dog and view its data.
<img style="width: 700px; height: 500px" src="/files/SQLi/website.png" alt="Website" align="center"></img>
As usual, the most basic test of an SQL server is a single quotation mark, `'`, because if the server doesn't filter this it will produce an syntax error in the SQL code. However, the website simply returned nothing, which means either the website applies input santization or handles error correctly. It seems that this is definately blind SQLi because no error message is ever returned.
Then I began to try some more complex basic tests. `1 OR 1 = 1` is a very common test to tell whether a field is subject to injection. If the server does not handle the search properly it would return all the contents of the table. Sure enough, the server returned all the information of all three dogs.

# Further tests
I then tried a very similar approach, `1 OR '1' = '1'`. However, this time the command did not work and the website returned 0 results. This made no sense to me at first because the server is definately using an SQL query in the form `"SELECT * FROM Dogs WHERE ID = '$_GET["ID"]'"` and `'1' = '1'` is equivalent to `True` in any SQL query just like `1 = 1`. I tried a lot others such as `1 AND 1 = 1` `1 OR '1' = '2'`, but it turned out that whenever their's a single quotation mark the query would fail.

Then it came to me that the author must have made an input santization that invalidates the use of `'`, returning empty results whenever a query contains `'`.

With this in mind I tried some more routine tests such as `1+1`, `2 + (SELECT 0/1)` and so on, all of which worked as expected from an SQL vulnerable server.

If one wants to get private data from an SQL injectable server, the `UNION` operator is almost always used. However, when I entered `1 UNION SELECT 1` the website again returned nothing. I wondered how the could happen. First I tried to end the SQL query with `1 UNION SELECT 1 --`. Still, nothing returned.

I thought for a long time, before I found out that each dog have at least 3 columns in the database, `Name`, `Breed` and `Color`. Could it be that there is an error due to the dimension mismatch? I searched for an only SQL simulator and entered the following command.

<img style="width: 1000px; height: 500px" src="/files/SQLi/mismatch.png" alt="Website" align="center"></img>

Yeah, so I was right, I need the same number of columns in the second select command. Intuitively, I entered `1 UNION SELECT 1, 1, 1`. Still, 0 results. Maybe the query actually asked for more than 3 columns? I entered `1 UNION SELECT 1, 1, 1, 1` and

<img style="width: 700px; height: 500px" src="/files/SQLi/union-success.png" alt="Website" align="center"></img>

Yeah.

# Injection
Now I began to make my attempt for the actual injection. First I need to know the SQL backend so I can select commands accordingly. `@@version` returns the version information on Microsoft SQL and MySQL which most servers choose to use. To get the information, I entered `1 UNION SELECT NULL, @@version, NULL, NULL` and got the following:

<img style="width: 700px; height: 500px" src="/files/SQLi/version.png" alt="Website" align="center"></img>
A quick search tells me that this is an MySQL version information. However, I still need to know which table and which column I should get the flag from. [A post on stack overflow](https://stackoverflow.com/questions/8334493/get-table-names-using-select-statement-in-mysql) told me how to get table names using a select statement, which is all I need for an `UNION` statement to work. The final statement is `1 union select NULL, table_name, NULL, NULL from information_schema.tables` and I got a huge list of table names:
![Table Name List](/files/SQLi/table_names.png)
According to the naming conventions of CTF problems, the table name is obviously `w0w_y0u_f0und_m3`. Using similar techniques, the column name is found to be `f0und_m3`. Therefore, the last thing to do is simply `1 union select NULL, f0und_m3, NULL, NULL from w0w_y0u_f0und_m3` and the key is finally revealed:
![flag](/files/SQLi/flag.png)

# Conclusion

I learn't a lot from this problem about SQL injection. Although this problem took much shorter than I expected, I learnt about the basic techniques, methods and sequence of an SQL attack.