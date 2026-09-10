* ============================================================
* gen_fixtures.prg - DBF_Anonymizer REQ-P0-003 synthetic fixture generator
* Deterministic constants only. No real data. No absolute paths in artifacts.
* All CDX / DBC / IDX structures are created by Visual FoxPro itself.
* ============================================================
SET SAFETY OFF
SET TALK OFF
SET EXCLUSIVE ON
SET NOTIFY OFF
SET CPDIALOG OFF
CLOSE ALL
lcLog = "vfp_gen_log.txt"
STRTOFILE("=== VFP synthetic fixture generation ===" + CHR(13) + CHR(10), lcLog, .F.)
STRTOFILE("VFP_VERSION=" + VERSION() + CHR(13) + CHR(10), lcLog, .T.)

* ---------- cleanup of possible prior runs ----------
IF FILE("structural\indexed_table.dbf")
    ERASE structural\indexed_table.dbf
ENDIF
IF FILE("structural\indexed_table.cdx")
    ERASE structural\indexed_table.cdx
ENDIF
IF FILE("dbc\dbc_bound_table.dbf")
    ERASE dbc\dbc_bound_table.dbf
ENDIF
IF FILE("fixture.dbc")
    ERASE fixture.dbc
ENDIF
IF FILE("fixture.dct")
    ERASE fixture.dct
ENDIF
IF FILE("fixture.dcx")
    ERASE fixture.dcx
ENDIF
IF FILE("idx\standalone_idx_table.dbf")
    ERASE idx\standalone_idx_table.dbf
ENDIF
IF FILE("idx\code_idx.idx")
    ERASE idx\code_idx.idx
ENDIF
IF FILE("code_idx.idx")
    ERASE code_idx.idx
ENDIF
STRTOFILE("cleanup_done" + CHR(13) + CHR(10), lcLog, .T.)

* ---------- A. STRUCTURAL CDX FIXTURE (free table) ----------
CREATE TABLE structural\indexed_table FREE (CODE C(10), AMOUNT N(10,2), NOTE C(20))
INSERT INTO structural\indexed_table (CODE, AMOUNT, NOTE) VALUES ("KEY0001", 100, "SYNTH-A")
INSERT INTO structural\indexed_table (CODE, AMOUNT, NOTE) VALUES ("KEY0002", 200, "SYNTH-B")
INSERT INTO structural\indexed_table (CODE, AMOUNT, NOTE) VALUES ("KEY0003", 100, "SYNTH-A")
INSERT INTO structural\indexed_table (CODE, AMOUNT, NOTE) VALUES ("KEY0004", 200, "SYNTH-B")
INDEX ON CODE TAG SYNTHCODE
INDEX ON NOTE TAG SYNTHNOTE
USE

* close and reopen; verify the CDX is attached as structural
USE structural\indexed_table EXCLUSIVE
lnTags  = TAGCOUNT()
lcCdx1  = JUSTFNAME(CDX(1))
lcTag1  = TAG(1)
lcExpr1 = SYS(14, 1)
lcTag2  = TAG(2)
lcExpr2 = SYS(14, 2)
SET ORDER TO TAG SYNTHCODE
lcOrd = ORDER()
lnRecA = RECCOUNT()
lcFA = FIELD(1) + "," + FIELD(2) + "," + FIELD(3)
STRTOFILE("A_RESULT cdx1=" + lcCdx1 + ;
          " tagcount=" + LTRIM(STR(lnTags)) + ;
          " tag1=" + lcTag1 + " expr1=" + lcExpr1 + ;
          " tag2=" + lcTag2 + " expr2=" + lcExpr2 + ;
          " order=" + lcOrd + ;
          " reccount=" + LTRIM(STR(lnRecA)) + ;
          " fields=" + lcFA + CHR(13) + CHR(10), lcLog, .T.)
USE

* ---------- B. DBC-BOUND FIXTURE (minimal container) ----------
CREATE DATABASE fixture
CREATE TABLE dbc\dbc_bound_table (CODE C(10), AMOUNT N(10,2), NOTE C(20))
INSERT INTO dbc\dbc_bound_table (CODE, AMOUNT, NOTE) VALUES ("KEY0001", 100, "SYNTH-A")
INSERT INTO dbc\dbc_bound_table (CODE, AMOUNT, NOTE) VALUES ("KEY0002", 200, "SYNTH-B")
INSERT INTO dbc\dbc_bound_table (CODE, AMOUNT, NOTE) VALUES ("KEY0003", 100, "SYNTH-A")
INSERT INTO dbc\dbc_bound_table (CODE, AMOUNT, NOTE) VALUES ("KEY0004", 200, "SYNTH-B")
lcDbcOpen = JUSTFNAME(DBC())
lnInDbc = INDBC("dbc_bound_table", "TABLE")
USE
lcDbcAfterClose = DBC()
CLOSE DATABASES

* reopen: verify database opens, table belongs to it, table opens
OPEN DATABASE fixture
USE dbc\dbc_bound_table EXCLUSIVE
lcDbcReopen = JUSTFNAME(DBC())
lnInDbcReopen = INDBC("dbc_bound_table", "TABLE")
lnRecB = RECCOUNT()
lcFB = FIELD(1) + "," + FIELD(2) + "," + FIELD(3)
STRTOFILE("B_RESULT open_dbc=" + lcDbcOpen + ;
          " in_dbc_at_create=" + IIF(lnInDbc, "T", "F") + ;
          " dbc_value_after_close=[" + lcDbcAfterClose + "]" + ;
          " reopen_dbc=" + lcDbcReopen + ;
          " in_dbc_reopen=" + IIF(lnInDbcReopen, "T", "F") + ;
          " reccount=" + LTRIM(STR(lnRecB)) + ;
          " fields=" + lcFB + CHR(13) + CHR(10), lcLog, .T.)
USE
CLOSE DATABASES

* ---------- C. STANDALONE IDX FIXTURE (free table) ----------
CD idx
CREATE TABLE standalone_idx_table FREE (CODE C(10), AMOUNT N(10,2), NOTE C(20))
INSERT INTO standalone_idx_table (CODE, AMOUNT, NOTE) VALUES ("KEY0001", 100, "SYNTH-A")
INSERT INTO standalone_idx_table (CODE, AMOUNT, NOTE) VALUES ("KEY0002", 200, "SYNTH-B")
INSERT INTO standalone_idx_table (CODE, AMOUNT, NOTE) VALUES ("KEY0003", 100, "SYNTH-A")
INSERT INTO standalone_idx_table (CODE, AMOUNT, NOTE) VALUES ("KEY0004", 200, "SYNTH-B")
INDEX ON CODE TO code_idx
USE

* close and reopen; explicitly reopen/use the standalone IDX
USE standalone_idx_table EXCLUSIVE
SET INDEX TO code_idx.idx
SET ORDER TO 1
lcNdx1 = JUSTFNAME(NDX(1))
lcIdxExpr = SYS(14, 1)
lcIdxOrd = ORDER()
lnRecC = RECCOUNT()
lcFC = FIELD(1) + "," + FIELD(2) + "," + FIELD(3)
USE
CD ..
STRTOFILE("C_RESULT ndx1=" + lcNdx1 + ;
          " expr=" + lcIdxExpr + ;
          " order=" + lcIdxOrd + ;
          " reccount=" + LTRIM(STR(lnRecC)) + ;
          " fields=" + lcFC + CHR(13) + CHR(10), lcLog, .T.)

STRTOFILE("=== ALL DONE ===" + CHR(13) + CHR(10), lcLog, .T.)
