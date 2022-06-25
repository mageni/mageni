##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB.nasl 13840 2019-02-25 08:29:29Z cfischer $
#
# IT-Grundschutz, 14. Ergänzungslieferung
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Modified:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

massnahmen = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005",
"M4_006", "M4_007", "M4_008", "M4_009", "M4_010", "M4_011", "M4_012", "M4_013",
"M4_014", "M4_015", "M4_016", "M4_017", "M4_018", "M4_019", "M4_020", "M4_021",
"M4_022", "M4_023", "M4_024", "M4_025", "M4_026", "M4_027", "M4_028", "M4_029",
"M4_030", "M4_031", "M4_032", "M4_033", "M4_034", "M4_035", "M4_036", "M4_037",
"M4_038", "M4_039", "M4_040", "M4_041", "M4_042", "M4_043", "M4_044", "M4_045",
"M4_046", "M4_047", "M4_048", "M4_049", "M4_050", "M4_051", "M4_052", "M4_053",
"M4_054", "M4_055", "M4_056", "M4_057", "M4_058", "M4_059", "M4_060", "M4_061",
"M4_062", "M4_063", "M4_064", "M4_065", "M4_066", "M4_067", "M4_068", "M4_069",
"M4_070", "M4_071", "M4_072", "M4_073", "M4_074", "M4_075", "M4_076", "M4_077",
"M4_078", "M4_079", "M4_080", "M4_081", "M4_082", "M4_083", "M4_084", "M4_085",
"M4_086", "M4_087", "M4_088", "M4_089", "M4_090", "M4_091", "M4_092", "M4_093",
"M4_094", "M4_095", "M4_096", "M4_097", "M4_098", "M4_099", "M4_100", "M4_101",
"M4_102", "M4_103", "M4_104", "M4_105", "M4_106", "M4_107", "M4_108", "M4_109",
"M4_110", "M4_111", "M4_112", "M4_113", "M4_114", "M4_115", "M4_116", "M4_117",
"M4_118", "M4_119", "M4_120", "M4_121", "M4_122", "M4_123", "M4_124", "M4_125",
"M4_126", "M4_127", "M4_128", "M4_129", "M4_130", "M4_131", "M4_132", "M4_133",
"M4_134", "M4_135", "M4_136", "M4_137", "M4_138", "M4_139", "M4_140", "M4_141",
"M4_142", "M4_143", "M4_144", "M4_145", "M4_146", "M4_147", "M4_148", "M4_149",
"M4_150", "M4_151", "M4_152", "M4_153", "M4_154", "M4_155", "M4_156", "M4_157",
"M4_158", "M4_159", "M4_160", "M4_161", "M4_162", "M4_163", "M4_164", "M4_165",
"M4_166", "M4_167", "M4_168", "M4_169", "M4_170", "M4_171", "M4_172", "M4_173",
"M4_174", "M4_175", "M4_176", "M4_177", "M4_178", "M4_179", "M4_180", "M4_181",
"M4_182", "M4_183", "M4_184", "M4_185", "M4_186", "M4_187", "M4_188", "M4_189",
"M4_190", "M4_191", "M4_192", "M4_193", "M4_194", "M4_195", "M4_196", "M4_197",
"M4_198", "M4_199", "M4_200", "M4_201", "M4_202", "M4_203", "M4_204", "M4_205",
"M4_206", "M4_207", "M4_208", "M4_209", "M4_210", "M4_211", "M4_212", "M4_213",
"M4_214", "M4_215", "M4_216", "M4_217", "M4_218", "M4_219", "M4_220", "M4_221",
"M4_222", "M4_223", "M4_224", "M4_225", "M4_226", "M4_227", "M4_228", "M4_229",
"M4_230", "M4_231", "M4_232", "M4_233", "M4_234", "M4_235", "M4_236", "M4_237",
"M4_238", "M4_239", "M4_240", "M4_241", "M4_242", "M4_243", "M4_244", "M4_245",
"M4_246", "M4_247", "M4_248", "M4_249", "M4_250", "M4_251", "M4_252", "M4_253",
"M4_254", "M4_255", "M4_256", "M4_257", "M4_258", "M4_259", "M4_260", "M4_261",
"M4_262", "M4_263", "M4_264", "M4_265", "M4_266", "M4_267", "M4_268", "M4_269",
"M4_270", "M4_271", "M4_272", "M4_273", "M4_274", "M4_275", "M4_276", "M4_277",
"M4_278", "M4_279", "M4_280", "M4_281", "M4_282", "M4_283", "M4_284", "M4_285",
"M4_286", "M4_287", "M4_288", "M4_289", "M4_290", "M4_291", "M4_292", "M4_293",
"M4_294", "M4_295", "M4_296", "M4_297", "M4_298", "M4_299", "M4_300", "M4_301",
"M4_302", "M4_303", "M4_304", "M4_305", "M4_306", "M4_307", "M4_308", "M4_309",
"M4_310", "M4_311", "M4_312", "M4_313", "M4_314", "M4_315", "M4_316", "M4_317",
"M4_318", "M4_319", "M4_320", "M4_321", "M4_322", "M4_323", "M4_324", "M4_325",
"M4_326", "M4_327", "M4_328", "M4_329", "M4_330", "M4_331", "M4_332", "M4_333",
"M4_334", "M4_335", "M4_336", "M4_337", "M4_338", "M4_339", "M4_340", "M4_341",
"M4_342", "M4_343", "M4_344", "M4_345", "M4_346", "M4_347", "M4_348", "M4_349",
"M4_350", "M4_351", "M4_352", "M4_353", "M4_354", "M4_355", "M4_356", "M4_357",
"M4_358", "M4_359", "M4_360", "M4_361", "M4_362", "M4_363", "M4_364", "M4_365",
"M4_366", "M4_367", "M4_368", "M4_369", "M4_370", "M4_371", "M4_372", "M4_373",
"M4_374", "M4_375", "M4_376", "M4_377", "M4_378", "M4_379", "M4_380", "M4_381",
"M4_382", "M4_383", "M4_384", "M4_385", "M4_386", "M4_387", "M4_388", "M4_389",
"M4_390", "M4_391", "M4_392", "M4_393", "M4_394", "M4_395", "M4_396", "M4_397",
"M4_398", "M4_399", "M4_400", "M4_401", "M4_402", "M4_403", "M4_404", "M4_405",
"M4_406", "M4_407", "M4_408", "M4_409", "M4_410", "M4_411", "M4_412", "M4_413",
"M4_414", "M4_415", "M4_416", "M4_417", "M4_418", "M4_419", "M4_420", "M4_421",
"M4_422", "M4_423", "M4_424", "M4_425", "M4_426", "M4_427", "M4_428", "M4_429",
"M4_430", "M4_431", "M4_432", "M4_434", "M4_435", "M4_436", "M4_437", "M4_438",
"M4_439", "M4_440", "M4_441", "M4_442", "M4_443", "M4_444", "M4_445", "M4_446",
"M4_447", "M4_448", "M4_449", "M4_450", "M4_451", "M4_452", "M4_453", "M4_454",
"M4_455", "M4_456", "M4_457", "M4_458", "M4_459", "M4_460", "M4_461", "M4_462",
"M4_463", "M4_464", "M4_465", "M4_466", "M4_467", "M4_468", "M4_469", "M4_470",
"M4_471", "M4_472", "M4_473", "M4_474", "M4_475", "M4_476", "M4_477", "M4_478",
"M4_479", "M4_480", "M4_481", "M4_482", "M4_483", "M4_484", "M4_485", "M4_486",
"M4_487", "M4_488", "M4_489", "M4_490", "M4_491", "M4_492", "M4_493", "M4_494",
"M4_495", "M4_496", "M4_497", "M4_498", "M4_499", "M4_500", "M5_001",
"M5_002", "M5_003", "M5_004", "M5_005", "M5_006", "M5_007", "M5_008", "M5_009",
"M5_010", "M5_011", "M5_012", "M5_013", "M5_014", "M5_015", "M5_016", "M5_017",
"M5_018", "M5_019", "M5_020", "M5_021", "M5_022", "M5_023", "M5_024", "M5_025",
"M5_026", "M5_027", "M5_028", "M5_029", "M5_030", "M5_031", "M5_032", "M5_033",
"M5_034", "M5_035", "M5_036", "M5_037", "M5_038", "M5_039", "M5_040", "M5_041",
"M5_042", "M5_043", "M5_044", "M5_045", "M5_046", "M5_047", "M5_048", "M5_049",
"M5_050", "M5_051", "M5_052", "M5_053", "M5_054", "M5_055", "M5_056", "M5_057",
"M5_058", "M5_059", "M5_060", "M5_061", "M5_062", "M5_063", "M5_064", "M5_065",
"M5_066", "M5_067", "M5_068", "M5_069", "M5_070", "M5_071", "M5_072", "M5_073",
"M5_074", "M5_075", "M5_076", "M5_077", "M5_078", "M5_079", "M5_080", "M5_081",
"M5_082", "M5_083", "M5_084", "M5_085", "M5_086", "M5_087", "M5_088", "M5_089",
"M5_090", "M5_091", "M5_092", "M5_093", "M5_094", "M5_095", "M5_096", "M5_097",
"M5_098", "M5_099", "M5_100", "M5_101", "M5_102", "M5_103", "M5_104", "M5_105",
"M5_106", "M5_107", "M5_108", "M5_109", "M5_110", "M5_111", "M5_112", "M5_113",
"M5_114", "M5_115", "M5_116", "M5_117", "M5_118", "M5_119", "M5_120", "M5_121",
"M5_122", "M5_123", "M5_124", "M5_125", "M5_126", "M5_127", "M5_128", "M5_129",
"M5_130", "M5_131", "M5_132", "M5_133", "M5_134", "M5_135", "M5_136", "M5_137",
"M5_138", "M5_139", "M5_140", "M5_141", "M5_142", "M5_143", "M5_144", "M5_145",
"M5_146", "M5_147", "M5_148", "M5_149", "M5_150", "M5_151", "M5_152", "M5_153",
"M5_154", "M5_155", "M5_156", "M5_157", "M5_158", "M5_159", "M5_160", "M5_160",
"M5_161", "M5_162", "M5_163", "M5_164", "M5_165", "M5_166", "M5_167", "M5_168",
"M5_169", "M5_170", "M5_171", "M5_172", "M5_173", "M5_174", "M5_175", "M5_176",
"M5_177");

depend = make_list("M4_001", "M4_002", "M4_003", "M4_004", "M4_005", "M4_007",
 "M4_009", "M4_014", "M4_015", "M4_016", "M4_017", "M4_018", "M4_019", "M4_020",
 "M4_021", "M4_022", "M4_023", "M4_026", "M4_033", "M4_036", "M4_037",
 "M4_040", "M4_048", "M4_049", "M4_052", "M4_057", "M4_080", "M4_093", "M4_094",
 "M4_096", "M4_097", "M4_098", "M4_106", "M4_135", "M4_146", "M4_147",
 "M4_200", "M4_227", "M4_238", "M4_244", "M4_249", "M4_277", "M4_284", "M4_285",
 "M4_287", "M4_288", "M4_300", "M4_305", "M4_310", "M4_313", "M4_315", "M4_325",
 "M4_326", "M4_328", "M4_331", "M4_332", "M4_334", "M4_338", "M4_339", "M4_340",
 "M4_341", "M4_342", "M4_344", "M4_368", #"M4_420", "M4_423", "M4_425",
 "M5_008", "M5_009", "M5_017", "M5_018", "M5_019", "M5_020", "M5_021", "M5_034",
 "M5_059", "M5_063", "M5_064", "M5_066", "M5_072", "M5_090", "M5_091", "M5_109",
 "M5_123", "M5_131", "M5_145", "M5_147"
);

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94171");
  script_version("$Revision: 13840 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 09:29:29 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 15. EL");
  # Dependencies GSHB_M4_007.nasl and GSHB_M4_094.nasl are running in ACT_ATTACK because these depends on
  # GSHB_SSH_TELNET_BruteForce.nasl / GSHB_nikto.nasl which are in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Compliance");
  script_dependencies("compliance_tests.nasl");
  foreach d (depend)  script_dependencies("GSHB/EL15/GSHB_" + d + ".nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_require_keys("GSHB-15/silence");

  script_add_preference(name:"Berichtformat", type:"radio", value:"Text;Tabellarisch;Text und Tabellarisch");

  script_tag(name:"summary", value:"Zusammenfassung von Tests gemäß der IT-Grundschutz Kataloge
  mit Stand 15. Ergänzungslieferung.

  Diese Routinen prüfen sämtliche Maßnahmen des IT-Grundschutz des Bundesamts für Sicherheit
  in der Informationstechnik (BSI) auf den Zielsystemen soweit die Maßnahmen auf automatisierte
  Weise abgeprüft werden können.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

mtitel = "
M4.001 Passwortschutz für IT-Systeme
M4.002 Bildschirmsperre
M4.003 Einsatz von Viren-Schutzprogrammen
M4.004 Geeigneter Umgang mit Laufwerken für Wechselmedien und externen\n                Datenspeichern
M4.005 Protokollierung bei TK-Anlagen
M4.006 Revision der TK-Anlagenkonfiguration
M4.007 Änderung voreingestellter Passwörter
M4.008 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.009 Einsatz der Sicherheitsmechanismen von XWindow
M4.010 Schutz der TK-Endgeräte
M4.011 Absicherung der TK-Anlagen-Schnittstellen
M4.012 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.013 Sorgfältige Vergabe von IDs
M4.014 Obligatorischer Passwortschutz unter Unix
M4.015 Gesichertes Login
M4.016 Zugangsbeschränkungen für Benutzer-Kennungen und / oder\n                Terminals
M4.017 Sperren und Löschen nicht benötigter Accounts und Terminals
M4.018 Administrative und technische Absicherung des Zugangs zum\n                Monitor- und Single-User-Modus
M4.019 Restriktive Attributvergabe bei Unix-Systemdateien und\n                -verzeichnissen
M4.020 Restriktive Attributvergabe bei Unix-Benutzerdateien und\n                -verzeichnissen
M4.021 Verhinderung des unautorisierten Erlangens von\n                Administratorrechten
M4.022 Verhinderung des Vertraulichkeitsverlusts schutzbedürftiger\n                Daten im Unix-System
M4.023 Sicherer Aufruf ausführbarer Dateien
M4.024 Sicherstellung einer konsistenten Systemverwaltung
M4.025 Einsatz der Protokollierung im Unix-System
M4.026 Regelmäßiger Sicherheitscheck des Unix-Systems
M4.027 Zugriffsschutz am Laptop
M4.028 Software-Reinstallation bei Benutzerwechsel eines Laptops
M4.029 Einsatz eines Verschlüsselungsproduktes für tragbare IT-Systeme
M4.030 Nutzung der in Anwendungsprogrammen angebotenen\n                Sicherheitsfunktionen
M4.031 Sicherstellung der Energieversorgung im mobilen Einsatz
M4.032 Physikalisches Löschen der Datenträger vor und nach Verwendung
M4.033 Einsatz eines Viren-Suchprogramms bei Datenträgeraustausch und\n                Datenübertragung
M4.034 Einsatz von Verschlüsselung, Checksummen oder Digitalen\n                Signaturen
M4.035 Verifizieren der zu übertragenden Daten vor Versand
M4.036 Sperren bestimmter Faxempfänger- Rufnummern
M4.037 Sperren bestimmter Absender-Faxnummern
M4.038 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.039 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.040 Verhinderung der unautorisierten Nutzung von Rechnermikrofonen\n                und Kameras
M4.041 Einsatz angemessener Sicherheitsprodukte für IT-Systeme
M4.042 Implementierung von Sicherheitsfunktionalitäten in der\n                IT-Anwendung
M4.043 Faxgerät mit automatischer Eingangskuvertierung
M4.044 Diese Maßnahme ist mit Version 2005 entfallen
M4.045 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.046 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.047 Protokollierung der Sicherheitsgateway-Aktivitäten
M4.048 Passwortschutz unter Windows-Systemen
M4.049 Absicherung des Boot-Vorgangs für ein Windows System
M4.050 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.051 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.052 Geräteschutz unter NT-basierten Windows-Systemen
M4.053 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.054 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.055 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.056 Sicheres Löschen unter Windows-Betriebssystemen
M4.057 Deaktivieren der automatischen CD-ROM Erkennung
M4.058 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.059 Deaktivieren nicht benötigter ISDN-Karten-Funktionalitäten
M4.060 Deaktivieren nicht benötigter ISDN-Router-Funktionalitäten
M4.061 Nutzung vorhandener Sicherheitsmechanismen der ISDN-Komponenten
M4.062 Einsatz eines D-Kanal-Filters
M4.063 Sicherheitstechnische Anforderungen an den Telearbeitsrechner
M4.064 Verifizieren der zu übertragenden Daten vor Weitergabe / \n               Beseitigung von Restinformationen
M4.065 Test neuer Hard- und Software
M4.066 Diese Maßnahme ist mit Version 2004 entfallen
M4.067 Sperren und Löschen nicht benötigter Datenbank-Accounts
M4.068 Sicherstellung einer konsistenten Datenbankverwaltung
M4.069 Regelmäßiger Sicherheitscheck der Datenbank
M4.070 Durchführung einer Datenbanküberwachung
M4.071 Restriktive Handhabung von Datenbank-Links
M4.072 Datenbank-Verschlüsselung
M4.073 Festlegung von Obergrenzen für selektierbare Datensätze
M4.074 Diese Maßnahme ist mit der 10. Ergänzungslieferung entfallen
M4.075 Schutz der Registry unter Windows-Systemen
M4.076 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.077 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.078 Sorgfältige Durchführung von Konfigurationsänderungen
M4.079 Sichere Zugriffsmechanismen bei lokaler Administration
M4.080 Sichere Zugriffsmechanismen bei Fernadministration
M4.081 Audit und Protokollierung der Aktivitäten im Netz
M4.082 Sichere Konfiguration der aktiven Netzkomponenten
M4.083 Update/Upgrade von Soft- und Hardware im Netzbereich
M4.084 Nutzung der BIOS-Sicherheitsmechanismen
M4.085 Geeignetes Schnittstellendesign bei Kryptomodulen
M4.086 Sichere Rollenteilung und Konfiguration der Kryptomodule
M4.087 Physikalische Sicherheit von Kryptomodulen
M4.088 Anforderungen an die Betriebssystem-Sicherheit beim Einsatz von\n                Kryptomodulen
M4.089 Abstrahlsicherheit
M4.090 Einsatz von kryptographischen Verfahren auf den verschiedenen\n                Schichten des ISO/OSIReferenzmodells
M4.091 Sichere Installation eines Systemmanagementsystems
M4.092 Sicherer Betrieb eines Systemmanagementsystems
M4.093 Regelmäßige Integritätsprüfung
M4.094 Schutz der Webserver-Dateien
M4.095 Minimales Betriebssystem
M4.096 Abschaltung von DNS
M4.097 Ein Dienst pro Server
M4.098 Kommunikation durch Paketfilter auf Minimum beschränken
M4.099 Schutz gegen nachträgliche Veränderungen von Informationen
M4.100 Sicherheitsgateways und aktive Inhalte
M4.101 Sicherheitsgateways und Verschlüsselung
M4.102 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.103 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.104 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.105 Erste Maßnahmen nach einer Unix-Standardinstallation
M4.106 Aktivieren der Systemprotokollierung
M4.107 Nutzung von Hersteller- und Entwickler-Ressourcen
M4.108 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.109 Software-Reinstallation bei Arbeitsplatzrechnern
M4.110 Diese Maßnahme ist mit der 10. Ergänzungslieferung entfallen
M4.111 Diese Maßnahme ist mit der 10. Ergänzungslieferung entfallen
M4.112 Diese Maßnahme ist mit der 10. Ergänzungslieferung entfallen
M4.113 Nutzung eines Authentisierungsservers bei Remote-Access-VPNs
M4.114 Nutzung der Sicherheitsmechanismen von Mobiltelefonen
M4.115 Sicherstellung der Energieversorgung von Mobiltelefonen
M4.116 Sichere Installation von Lotus Notes/Domino
M4.117 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.118 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.119 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.120 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.121 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.122 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.123 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.124 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.125 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.126 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.127 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.128 Sicherer Betrieb der Lotus Notes/Domino-Umgebung
M4.129 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.130 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.131 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.132 Überwachung der Lotus Notes/Domino-Umgebung
M4.133 Geeignete Auswahl von Authentikationsmechanismen
M4.134 Wahl geeigneter Datenformate
M4.135 Restriktive Vergabe von Zugriffsrechten auf Systemdateien
M4.136 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.137 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.138 Konfiguration von Windows Server als Domänen-Controller
M4.139 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.140 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.141 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.142 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.143 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.144 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.145 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.146 Sicherer Betrieb von Windows Client Betriebssystemen
M4.147 Sichere Nutzung von EFS unter Windows
M4.148 Überwachung eines Windows 2000/XP Systems
M4.149 Datei- und Freigabeberechtigungen unter Windows
M4.150 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.151 Sichere Installation von Internet-PCs
M4.152 Sicherer Betrieb von Internet-PCs
M4.153 Sichere Installation von Novell eDirectory
M4.154 Sichere Installation der Novell eDirectory Clientsoftware
M4.155 Sichere Konfiguration von Novell eDirectory
M4.156 Sichere Konfiguration der Novell eDirectory Clientsoftware
M4.157 Einrichten von Zugriffsberechtigungen auf Novell eDirectory
M4.158 Einrichten des LDAP-Zugriffs auf Novell eDirectory
M4.159 Sicherer Betrieb von Novell eDirectory
M4.160 Überwachen von Novell eDirectory
M4.161 Sichere Installation von Exchange-Systemen
M4.162 Sichere Konfiguration von Exchange-Servern
M4.163 Zugriffsrechte auf Exchange-Objekte
M4.164 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.165 Sichere Konfiguration von Outlook
M4.166 Sicherer Betrieb von Exchange-Systemen
M4.167 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.168 Auswahl eines geeigneten Archivsystems
M4.169 Verwendung geeigneter Archivmedien
M4.170 Auswahl geeigneter Datenformate für die Archivierung von\n                Dokumenten
M4.171 Schutz der Integrität der Index-Datenbank von Archivsystemen
M4.172 Protokollierung der Archivzugriffe
M4.173 Regelmäßige Funktions- und Recoverytests bei der Archivierung
M4.174 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.175 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.176 Auswahl einer Authentisierungsmethode für Webangebote
M4.177 Sicherstellung der Integrität und Authentizität von\n                Softwarepaketen
M4.178 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.179 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.180 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.181 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.182 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.183 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.184 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.185 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.186 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.187 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.188 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.189 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.190 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.191 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.192 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.193 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.194 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.195 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.196 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.197 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M4.198 Installation einer Applikation in einem chroot Käfig
M4.199 Vermeidung problematischer Dateiformate
M4.200 Umgang mit USB-Speichermedien
M4.201 Sichere lokale Grundkonfiguration von Routern und Switches
M4.202 Sichere Netz-Grundkonfiguration von Routern und Switches
M4.203 Konfigurations-Checkliste für Router und Switches
M4.204 Sichere Administration von Routern und Switches
M4.205 Protokollierung bei Routern und Switches
M4.206 Sicherung von Switch-Ports
M4.207 Einsatz und Sicherung systemnaher z/OS-Terminals
M4.208 Absichern des Start-Vorgangs von z/OS-Systemen
M4.209 Sichere Grundkonfiguration von z/OS-Systemen
M4.210 Sicherer Betrieb des z/OS-Betriebssystems
M4.211 Einsatz des z/OS-Sicherheitssystems RACF
M4.212 Absicherung von Linux für zSeries
M4.213 Absichern des Login-Vorgangs unter z/OS
M4.214 Datenträgerverwaltung unter z/OS-Systemen
M4.215 Absicherung sicherheitskritischer z/OS-Dienstprogramme
M4.216 Festlegung der Systemgrenzen von z/OS
M4.217 Workload Management für z/OS-Systeme
M4.218 Hinweise zur Zeichensatzkonvertierung bei z/OS-Systemen
M4.219 Lizenzschlüssel-Management für z/OS-Software
M4.220 Absicherung von Unix System Services bei z/OS-Systemen
M4.221 Parallel-Sysplex unter z/OS
M4.222 Festlegung geeigneter Einstellungen von Sicherheitsproxies
M4.223 Integration von Proxy-Servern in das Sicherheitsgateway
M4.224 Integration von VPN-Komponenten in ein Sicherheitsgateway
M4.225 Einsatz eines Protokollierungsservers in einem\n                Sicherheitsgateway
M4.226 Integration von Virenscannern in ein Sicherheitsgateway
M4.227 Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation
M4.228 Nutzung der Sicherheitsmechanismen von Smartphones, Tablets \n  und PDAs
M4.229 Sicherer Betrieb von Smartphones, Tablets und PDAs
M4.230 Zentrale Administration von Smartphones, Tablets und PDAs
M4.231 Einsatz zusätzlicher Sicherheitswerkzeuge für Smartphones, \n   Tablets oder PDAs
M4.232 Sichere Nutzung von Zusatzspeicherkarten
M4.233 Diese Maßnahme ist mit der 10. Ergänzungslieferung entfallen
M4.234 Geregelte Außerbetriebnahme von IT-Systemen und Datenträgern
M4.235 Abgleich der Datenbestände von Laptops
M4.236 Zentrale Administration von Laptops
M4.237 Sichere Grundkonfiguration eines IT-Systems
M4.238 Einsatz eines lokalen Paketfilters
M4.239 Sicherer Betrieb eines Servers
M4.240 Einrichten einer Testumgebung für einen Server
M4.241 Sicherer Betrieb von Clients
M4.242 Einrichten einer Referenzinstallation für Clients
M4.243 Verwaltungswerkzeuge unter Windows Client-Betriebssystemen
M4.244 Sichere Systemkonfiguration von Windows Client-Betriebssystemen
M4.245 Basiseinstellungen für Windows Group Policy Objects
M4.246 Konfiguration der Systemdienste unter Windows XP, Vista und\n                Windows 7
M4.247 Restriktive Berechtigungsvergabe unter Windows Vista und\n                Windows 7
M4.248 Sichere Installation von Windows Client-Betriebssystemen
M4.249 Windows Client-Systeme aktuell halten
M4.250 Auswahl eines zentralen, netzbasierten Authentisierungsdienstes
M4.251 Arbeiten mit fremden IT-Systemen
M4.252 Sichere Konfiguration von Schulungsrechnern
M4.253 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M4.254 Sicherer Einsatz von drahtlosen Tastaturen und Mäusen
M4.255 Nutzung von IrDA-Schnittstellen
M4.256 Sichere Installation von SAP Systemen
M4.257 Absicherung des SAP Installationsverzeichnisses auf\n                Betriebssystemebene
M4.258 Sichere Konfiguration des SAP ABAP-Stacks
M4.259 Sicherer Einsatz der ABAP-Stack Benutzerverwaltung
M4.260 Berechtigungsverwaltung für SAP Systeme
M4.261 Sicherer Umgang mit kritischen SAP Berechtigungen
M4.262 Konfiguration zusätzlicher SAP Berechtigungsprüfungen
M4.263 Absicherung von SAP Destinationen
M4.264 Einschränkung von direkten Tabellenveränderungen in\n                SAP Systemen
M4.265 Sichere Konfiguration der Batch-Verarbeitung im SAP System
M4.266 Sichere Konfiguration des SAP Java-Stacks
M4.267 Sicherer Einsatz der SAP Java-Stack Benutzerverwaltung
M4.268 Sichere Konfiguration der SAP Java-Stack Berechtigungen
M4.269 Sichere Konfiguration der SAP System Datenbank
M4.270 SAP Protokollierung
M4.271 Virenschutz für SAP Systeme
M4.272 Sichere Nutzung des SAP Transportsystems
M4.273 Sichere Nutzung der SAP Java-Stack Software-Verteilung
M4.274 Sichere Grundkonfiguration von Speichersystemen
M4.275 Sicherer Betrieb einer Speicherlösung
M4.276 Planung des Einsatzes von Windows Server 2003
M4.277 Absicherung der SMB-, LDAP- und RPCKommunikation unter\n                Windows Servern
M4.278 Sichere Nutzung von EFS unter Windows Server 2003
M4.279 Erweiterte Sicherheitsaspekte für Windows Server 2003
M4.280 Sichere Basiskonfiguration ab Windows Server 2003
M4.281 Sichere Installation und Bereitstellung von Windows Server 2003
M4.282 Sichere Konfiguration der IIS-Basis-Komponente unter\nWindows\n                Server 2003
M4.283 Sichere Migration von Windows NT 4 Server und Windows 2000\n                Server auf Windows Server 2003
M4.284 Umgang mit Diensten ab Windows Server 2003
M4.285 Deinstallation nicht benötigter Client-Funktionen von\n                Windows Server 2003
M4.286 Verwendung der Softwareeinschränkungsrichtlinie unter\n                Windows Server 2003
M4.287 Sichere Administration der VoIP-Middleware
M4.288 Sichere Administration von VoIP-Endgeräten
M4.289 Einschränkung der Erreichbarkeit über VoIP
M4.290 Anforderungen an ein Sicherheitsgateway für den Einsatz von\n                VoIP
M4.291 Sichere Konfiguration der VoIP-Middleware
M4.292 Protokollierung bei VoIP
M4.293 Sicherer Betrieb von Hotspots
M4.294 Sichere Konfiguration der Access Points
M4.295 Sichere Konfiguration der WLAN-Clients
M4.296 Einsatz einer geeigneten WLAN-Management-Lösung
M4.297 Sicherer Betrieb der WLAN-Komponenten
M4.298 Regelmäßige Audits der WLAN-Komponenten
M4.299 Authentisierung bei Druckern, Kopierern und\n                Multifunktionsgeräten
M4.300 Informationsschutz bei Druckern, Kopierern und\n                Multifunktionsgeräten
M4.301 Beschränkung der Zugriffe auf Drucker, Kopierer und\n                Multifunktionsgeräte
M4.302 Protokollierung bei Druckern, Kopierern und\n                Multifunktionsgeräten
M4.303 Einsatz von netzfähigen Dokumentenscannern
M4.304 Verwaltung von Druckern
M4.305 Einsatz von Speicherbeschränkungen (Quotas)
M4.306 Umgang mit Passwort-Speicher-Tools
M4.307 Sichere Konfiguration von Verzeichnisdiensten
M4.308 Sichere Installation von Verzeichnisdiensten
M4.309 Einrichtung von Zugriffsberechtigungen auf Verzeichnisdienste
M4.310 Einrichtung des LDAP-Zugriffs auf Verzeichnisdienste
M4.311 Sicherer Betrieb von Verzeichnisdiensten
M4.312 Überwachung von Verzeichnisdiensten
M4.313 Bereitstellung von sicheren Domänen-Controllern
M4.314 Sichere Richtlinieneinstellungen für Domänen und\n                Domänen-Controller
M4.315 Aufrechterhaltung der Betriebssicherheit von Active Directory
M4.316 Überwachung der Active Directory Infrastruktur
M4.317 Sichere Migration von Windows Verzeichnisdiensten
M4.318 Umsetzung sicherer Verwaltungsmethoden für Active Directory
M4.319 Sichere Installation von VPN-Endgeräten
M4.320 Sichere Konfiguration eines VPNs
M4.321 Sicherer Betrieb eines VPNs
M4.322 Sperrung nicht mehr benötigter VPN-Zugänge
M4.323 Synchronisierung innerhalb des Patch- und Änderungsmanagements
M4.324 Konfiguration von Autoupdate-Mechanismen beim Patch- und\n                Änderungsmanagement
M4.325 Löschen von Auslagerungsdateien
M4.326 Sicherstellung der NTFS-Eigenschaften auf einem\n                Samba-Dateiserver
M4.327 Überprüfung der Integrität und Authentizität der Samba-Pakete\n                und-Quellen
M4.328 Sichere Grundkonfiguration eines Samba-Servers
M4.329 Sicherer Einsatz von Kommunikationsprotokollen beim Einsatz\n                eines Samba-Servers
M4.330 Sichere Installation eines Samba-Servers
M4.331 Sichere Konfiguration des Betriebssystems für einen\n                Samba-Server
M4.332 Sichere Konfiguration der Zugriffssteuerung bei einem\n                Samba-Server
M4.333 Sichere Konfiguration von Winbind unter Samba
M4.334 SMB Message Signing und Samba
M4.335 Sicherer Betrieb eines Samba-Servers
M4.336 Aktivierung von Windows-Systemen ab Vista bzw. Server 2008 aus\n                einem Volumenlizenzvertrag
M4.337 Einsatz von BitLocker Drive Encryption
M4.338 Einsatz von File und Registry Virtualization bei Clients ab\n               Windows Vista
M4.339 Verhindern unautorisierter Nutzung von Wechselmedien unter\n                Windows Vista und Windows 7
M4.340 Einsatz der Windows-Benutzerkontensteuerung UAC ab Windows\n                Vista
M4.341 Integritätsschutz ab Windows Vista
M4.342 Aktivierung des Last Access Zeitstempels ab Windows Vista
M4.343 Reaktivierung von Windows-Systemen ab Vista bzw. Server 2008\n                aus einem Volumenlizenzvertrag
M4.344 Überwachung von Windows-Systemen ab Windows Vista und \n					Windows Server 2008
M4.345 Schutz vor unerwünschten Informationsabflüssen
M4.346 Sichere Konfiguration virtueller IT-Systeme
M4.347 Deaktivierung von Snapshots virtueller IT-Systeme
M4.348 Zeitsynchronisation in virtuellen IT-Systemen
M4.349 Sicherer Betrieb von virtuellen Infrastrukturen
M4.350 Sichere Grundkonfiguration eines DNS-Servers
M4.351 Absicherung von Zonentransfers
M4.352 Absicherung von dynamischen DNS-Updates
M4.353 Einsatz von DNSSEC
M4.354 Überwachung eines DNS-Servers
M4.355 Berechtigungsverwaltung für Groupware-Systeme
M4.356 Sichere Installation von Groupware-Systemen
M4.357 Sicherer Betrieb von Groupware-Systemen
M4.358 Protokollierung von Groupware-Systemen
M4.359 Überblick über Komponenten eines Webservers
M4.360 Sichere Konfiguration eines Webservers
M4.361 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M4.362 Sichere Konfiguration von Bluetooth
M4.363 Sicherer Betrieb von Bluetooth-Geräten
M4.364 Regelungen für die Aussonderung von Bluetooth-Geräten
M4.365 Nutzung eines Terminalservers als grafische Firewall
M4.366 Sichere Konfiguration von beweglichen Benutzerprofilen in\n                Terminalserver-Umgebungen
M4.367 Sichere Verwendung von Client-Applikationen für Terminalserver
M4.368 Regelmäßige Audits der Terminalserver-Umgebung
M4.369 Sicherer Betrieb eines Anrufbeantworters
M4.370 Einsatz von Anoubis unter Unix
M4.371 Konfiguration von Mac OS X Clients
M4.372 Einsatz von FileVault unter Mac OS X
M4.373 Deaktivierung nicht benötigter Hardware unter Mac OS X
M4.374 Zugriffschutz der Benutzerkonten unter Mac OS X
M4.375 Einsatz der Sandbox-Funktion unter Mac OS X
M4.376 Festlegung von Passwortrichtlinien unter Mac OS X
M4.377 Überprüfung der Signaturen von Mac OS X Anwendungen
M4.378 Einschränkung der Programmzugriffe unter Mac OS X
M4.379 Sichere Datenhaltung und sicherer Transport unter Mac OS X
M4.380 Einsatz von Apple-Software-Restore unter Mac OS X
M4.381 Verschlüsselung von Exchange-System-Datenbanken
M4.382 Auswahl und Prüfung der OpenLDAP-Installationspakete
M4.383 Sichere Installation von OpenLDAP
M4.384 Sichere Konfiguration von OpenLDAP
M4.385 Konfiguration der durch OpenLDAP verwendeten Datenbank
M4.386 Einschränkung von Attributen bei OpenLDAP
M4.387 Sichere Vergabe von Zugriffsrechten auf OpenLDAP
M4.388 Sichere Authentisierung gegenüber OpenLDAP
M4.389 Partitionierung und Replikation bei OpenLDAP
M4.390 Sichere Aktualisierung von OpenLDAP
M4.391 Sicherer Betrieb von OpenLDAP
M4.392 Authentisierung bei Webanwendungen
M4.393 Umfassende Ein- und Ausgabevalidierung bei Webanwendungen und\n                Web-Services
M4.394 Session-Management bei Webanwendungen und Web-Services
M4.395 Fehlerbehandlung durch Webanwendungen und Web-Services
M4.396 Schutz vor unerlaubter automatisierter Nutzung von\n                Webanwendungen
M4.397 Protokollierung sicherheitsrelevanter Ereignisse von\n                Web-Anwendungen und Web-Services
M4.398 Sichere Konfiguration von Webanwendungen
M4.399 Kontrolliertes Einbinden von Daten und Inhalten bei\n                Webanwendungen
M4.400 Restriktive Herausgabe sicherheitsrelevanter Informationen bei\n                Webanwendungen und Web-Services
M4.401 Schutz vertraulicher Daten bei Webanwendungen
M4.402 Zugriffskontrolle bei Webanwendungen
M4.403 Verhinderung von Cross-Site Request Forgery (CSRF, XSRF,\n                Session Riding)
M4.404 Sicherer Entwurf der Logik von Webanwendungen
M4.405 Verhinderung der Blockade von Ressourcen (DoS) bei\n                Webanwendungen und Web-Services
M4.406 Verhinderung von Clickjacking
M4.407 Protokollierung beim Einsatz von OpenLDAP
M4.408 Übersicht über neue, sicherheitsrelevante Funktionen in\n                Windows Server 2008
M4.409 Beschaffung von Windows Server 2008
M4.410 Einsatz von Netzwerkzugriffsschutz unter Windows
M4.411 Sichere Nutzung von DirectAccess unter Windows
M4.412 Sichere Migration von Windows Server 2003 auf Server 2008
M4.413 Sicherer Einsatz von Virtualisierung mit Hyper-V
M4.414 Überblick über Neuerungen für Active Directory ab\n                Windows Server 2008
M4.415 Sicherer Betrieb der biometrischen Authentisierung unter\n                Windows
M4.416 Einsatz von Windows Server Core
M4.417 Patch-Management mit WSUS ab Windows Server 2008
M4.418 Planung des Einsatzes von Windows Server 2008
M4.419 Anwendungssteuerung ab Windows 7 mit AppLocker
M4.420 Sicherer Einsatz des Wartungscenters unter Windows 7
M4.421 Absicherung der Windows PowerShell
M4.422 Nutzung von BitLocker To Go ab Windows 7
M4.423 Verwendung der Heimnetzgruppen-Funktion unter Windows 7
M4.424 Sicherer Einsatz älterer Software unter Windows 7
M4.425 Verwendung der Tresor- und Cardspace-Funktion unter Windows 7
M4.426 Archivierung für die Lotus Notes/Domino-Umgebung
M4.427 Sicherheitsrelevante Protokollierung und Auswertung für Lotus\n                Notes/Domino
M4.428 Audit der Lotus Notes/Domino-Umgebung
M4.429 Sichere Konfiguration von Lotus Notes/Domino
M4.430 Analyse von Protokolldaten
M4.431 Auswahl und Verarbeitung relevanter Informationen für die\n                Protokollierung
M4.432 Sichere Konfiguration von Serverdiensten
M4.433 Einsatz von Datenträgerverschlüsselung
M4.434 Sicherer Einsatz von Appliances
M4.435 Selbstverschlüsselnde Festplatten
M4.436 Planung der Ressourcen für Cloud-Dienste
M4.437 Planung von Cloud-Diensteprofilen
M4.438 Auswahl von Cloud-Komponenten
M4.439 Virtuelle Sicherheitsgateways (Firewalls) in Clouds
M4.440 Verschlüsselte Speicherung von Cloud-Anwenderdaten
M4.441 Multifaktor-Authentisierung für den Cloud-Benutzerzugriff
M4.442 Zentraler Schutz vor Schadprogrammen in der Cloud-Infrastruktur
M4.443 Protokollierung und Monitoring von Ereignissen in der\n                Cloud-Infrastruktur
M4.444 Patchmanagement für Cloud-Komponenten
M4.445 Durchgängige Mandantentrennung von Cloud-Diensten
M4.446 Einführung in das Cloud Management
M4.447 Sicherstellung der Integrität der SAN-Fabric
M4.448 Einsatz von Verschlüsselung für Speicherlösungen
M4.449 Einführung eines Zonenkonzeptes
M4.450 Absicherung der Kommunikation bei Web-Services
M4.451 Aktuelle Web-Service Standards
M4.452 Überwachung eines Web-Service
M4.453 Einsatz eines Security Token Service (STS)
M4.454 Schutz vor unerlaubter Nutzung von Web-Services
M4.455 Autorisierung bei Web-Services
M4.456 Authentisierung bei Web-Services
M4.457 Sichere Mandantentrennung bei Webanwendungen und Web-Services
M4.458 Planung des Einsatzes von Web-Services
M4.459 Einsatz von Verschlüsselung bei Cloud-Nutzung
M4.460 Einsatz von Federation Services
M4.461 Portabilität von Cloud Services
M4.462 Einführung in die Cloud-Nutzung
M4.463 Sichere Installation einer Anwendung
M4.464 Aufrechterhaltung der Sicherheit im laufenden Anwendungs-\n                betrieb
M4.465 Aussonderung von Mobiltelefonen, Smartphones, Tablets und PDAs
M4.466 Einsatz von Viren-Schutzprogrammen bei Smartphones, Tablets\n                und PDAs
M4.467 Auswahl von Applikationen für Smartphones, Tablets und PDAs
M4.468 Trennung von privatem und dienstlichem Bereich auf Smartphones,\n            Tablets und PDAs
M4.469 Abwehr von eingeschleusten GSM-Codes auf Endgeräten mit\n								 Telefonfunktion
M4.470 Grundlagenwissen zu Windows 8
M4.471 Übersicht über neue, sicherheitsrelevante Funktionen in Windows 8
M4.472 Datensparsamkeit bei Windows 8
M4.473 Schutz vor Abhören von XML-Transportcontainern in einer SOA
M4.474 Schutz vor Schwachstellen in Backend-Anwendungen einer SOA
M4.475 Schutz vor Spoofing-Angriffen auf Identitätsdienste
M4.476 Schutz einer WS-Notification-Subscription im Broker
M4.477 Schutz einer WS-Notification
M4.478 Schlüsselmittelverwaltung bei SOA
M4.479 Schutz von Richtlinien in einer SOA
M4.480 Schutz von WS-Resource in SOA-Umgebungen
M4.481 Sichere Nutzung verbindungsloser SOAP-Kommunikation
M4.482 Hardware-Realisierung von Funktionen eingebetteter Systeme
M4.483 Einsatz kryptographischer Prozessoren bzw. Koprozessoren \n                  (Trusted Platform Module) bei eingebetteten Systemen
M4.484 Speicherschutz bei eingebetteten Systemen
M4.485 Sicheres Betriebssystem für eingebettete Systeme
M4.486 Widerstandsfähigkeit eingebetteter Systeme gegen Seitenkanalangriffe
M4.487 Tamper-Schutz (Erkennung, Verhinderung, Abwehr) bei \n                   eingebetteten Systemen
M4.488 Deaktivieren nicht benutzter Schnittstellen und Dienste bei \n               eingebetteten Systemen
M4.489 Abgesicherter und authentisierter Bootprozess bei eingebetteten Systemen
M4.490 Automatische Überwachung der Baugruppenfunktion (BIST) bei \n                eingebetteten Systemen
M4.491 Verhindern von Debugging-Möglichkeiten bei eingebetteten Systemen
M4.492 Sichere Konfiguration und Nutzung eines eingebetteten Webservers
M4.493 Auswahl einer Entwicklungsumgebung für die Software-Entwicklung
M4.494 Sicherer Einsatz einer Entwicklungsumgebung
M4.495 Sicheres Systemdesign bei der Software-Entwicklung
M4.496 Sichere Installation der entwickelten Software
M4.497 Sichere Installation eines Netzmanagement-Systems
M4.498 Sicherer Einsatz von Single-Sign-On
M4.499 Geeignete Auswahl von Identitäts- und\n										 Berechtigungsmanagement-Systemen
M4.500 Sicherer Einsatz von Systemen für Identitäts- und \n               Berechtigungsmanagement
M5.001 Entfernen oder Deaktivieren nicht benötigter Leitungen
M5.002 Auswahl einer geeigneten Netz-Topologie
M5.003 Auswahl geeigneter Kabeltypen unter kommunikationstechnischer\n                Sicht
M5.004 Dokumentation und Kennzeichnung der Verkabelung
M5.005 Schadensmindernde Kabelführung
M5.006 Diese Maßnahme ist mit Version 2005 entfallen
M5.007 Netzverwaltung
M5.008 Regelmäßiger Sicherheitscheck des Netzes
M5.009 Protokollierung am Server
M5.010 Restriktive Rechtevergabe
M5.011 Diese Maßnahme ist mit Version 2005 entfallen
M5.012 Diese Maßnahme ist mit Version 2005 entfallen
M5.013 Geeigneter Einsatz von Elementen zur Netzkopplung
M5.014 Absicherung interner Remote-Zugänge von TK-Anlagen
M5.015 Absicherung externer Remote-Zugänge von TK-Anlagen
M5.016 Übersicht über Netzdienste
M5.017 Einsatz der Sicherheitsmechanismen von NFS
M5.018 Einsatz der Sicherheitsmechanismen von NIS
M5.019 Einsatz der Sicherheitsmechanismen von sendmail
M5.020 Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp
M5.021 Sicherer Einsatz von telnet, ftp, tftp und rexec
M5.022 Kompatibilitätsprüfung des Sender- und Empfängersystems
M5.023 Auswahl einer geeigneten Versandart für Datenträger
M5.024 Nutzung eines geeigneten Faxvorblattes
M5.025 Nutzung von Sende- und Empfangsprotokollen
M5.026 Telefonische Ankündigung einer Faxsendung
M5.027 Telefonische Rückversicherung über korrekten Faxempfang
M5.028 Telefonische Rückversicherung über korrekten Faxabsender
M5.029 Gelegentliche Kontrolle programmierter Zieladressen und\n                Protokolle
M5.030 Aktivierung einer vorhandenen Callback-Option
M5.031 Geeignete Modem-Konfiguration
M5.032 Sicherer Einsatz von Kommunikationssoftware
M5.033 Absicherung von Fernwartung
M5.034 Einsatz von Einmalpasswörtern
M5.035 Einsatz der Sicherheitsmechanismen von UUCP
M5.036 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.037 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.038 Diese Maßnahme ist mit Version 2006 entfallen
M5.039 Sicherer Einsatz der Protokolle und Dienste
M5.040 Diese Maßnahme ist mit Version 2006 entfallen
M5.041 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.042 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.043 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.044 Einseitiger Verbindungsaufbau
M5.045 Sicherheit von Browsern
M5.046 Einsatz von Stand-alone-Systemen zur Nutzung des Internets
M5.047 Einrichten einer Closed User Group
M5.048 Authentisierung mittels CLIP/COLP
M5.049 Callback basierend auf CLIP/COLP
M5.050 Authentisierung mittels PAP/CHAP
M5.051 Sicherheitstechnische Anforderungen an die Kommunikations-\n                verbindung Telearbeitsrechner - Institution
M5.052 Sicherheitstechnische Anforderungen an den\n                Kommunikationsrechner
M5.053 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.054 Umgang mit unerwünschten E-Mails
M5.055 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.056 Sicherer Betrieb eines Mailservers
M5.057 Sichere Konfiguration der Groupware-/Mail-Clients
M5.058 Auswahl und Installation von Datenbankschnittstellen-Treibern
M5.059 Schutz vor DNS-Spoofing bei Authentisierungsmechanismen
M5.060 Auswahl einer geeigneten Backbone-Technologie
M5.061 Geeignete physikalische Segmentierung
M5.062 Geeignete logische Segmentierung
M5.063 Einsatz von GnuPG oder PGP
M5.064 Secure Shell
M5.065 Diese Maßnahme ist mit Version 2005 entfallen
M5.066 Clientseitige Verwendung von SSL/TLS
M5.067 Verwendung eines Zeitstempel-Dienstes
M5.068 Einsatz von Verschlüsselungsverfahren zur Netzkommunikation
M5.069 Schutz vor aktiven Inhalten
M5.070 Adreßumsetzung - NAT (Network Address Translation)
M5.071 Intrusion Detection und Intrusion Response Systeme
M5.072 Deaktivieren nicht benötigter Netzdienste
M5.073 Sicherer Betrieb eines Faxservers
M5.074 Pflege der Faxserver-Adressbücher und der Verteillisten
M5.075 Schutz vor Überlastung des Faxservers
M5.076 Einsatz geeigneter Tunnel-Protokolle für die VPN-Kommunikation
M5.077 Bildung von Teilnetzen
M5.078 Schutz vor Erstellen von Bewegungsprofilen bei der\n                Mobiltelefon-Nutzung
M5.079 Schutz vor Rufnummernermittlung bei der Mobiltelefon-Nutzung
M5.080 Schutz vor Abhören der Raumgespräche über Mobiltelefone
M5.081 Sichere Datenübertragung über Mobiltelefone
M5.082 Diese Maßnahme ist mit der 11. Ergänzungslieferung entfallen
M5.083 Diese Maßnahme ist mit der 15. Ergänzungslieferung entfallen
M5.084 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M5.085 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M5.086 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M5.087 Vereinbarung über die Anbindung an Netze Dritter
M5.088 Vereinbarung über Datenaustausch mit Dritten
M5.089 Konfiguration des sicheren Kanals unter Windows
M5.090 Einsatz von IPSec unter Windows
M5.091 Einsatz von Personal Firewalls für Clients
M5.092 Sichere Internet-Anbindung von Internet-PCs
M5.093 Sicherheit von WWW-Browsern bei der Nutzung von Internet-PCs
M5.094 Sicherheit von E-Mail-Clients bei der Nutzung von Internet-PCs
M5.095 Sicherer E-Commerce bei der Nutzung von Internet-PCs
M5.096 Sichere Nutzung von Webmail
M5.097 Absicherung der Kommunikation mit Novell eDirectory
M5.098 Schutz vor Missbrauch kostenpflichtiger Einwahlnummern
M5.099 Diese Maßnahme ist mit der 13. Ergänzungslieferung entfallen
M5.100 Absicherung der Kommunikation von und zu Exchange Systemen
M5.101 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.102 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.103 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.104 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.105 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.106 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.107 Diese Maßnahme ist mit der 12. Ergänzungslieferung entfallen
M5.108 Kryptographische Absicherung von Groupware bzw. E-Mail
M5.109 Einsatz eines E-Mail-Scanners auf dem Mailserver
M5.110 Absicherung von E-Mail mit SPHINX (S/MIME)
M5.111 Einrichtung von Access Control Lists auf Routern
M5.112 Sicherheitsaspekte von Routing-Protokollen
M5.113 Einsatz des VTAM Session Management Exit unter z/OS
M5.114 Absicherung der z/OS-Tracefunktionen
M5.115 Integration eines Webservers in ein Sicherheitsgateway
M5.116 Integration eines E-Mailservers in ein Sicherheitsgateway
M5.117 Integration eines Datenbank-Servers in ein Sicherheitsgateway
M5.118 Integration eines DNS-Servers in ein Sicherheitsgateway
M5.119 Integration einer Web-Anwendung mit Web-,Applikations- und\n                Datenbank-Server in ein Sicherheitsgateway
M5.120 Behandlung von ICMP am Sicherheitsgateway
M5.121 Sichere Kommunikation von unterwegs
M5.122 Sicherer Anschluss von Laptops an lokale Netze
M5.123 Absicherung der Netzkommunikation unter Windows
M5.124 Netzzugänge in Besprechungs-, Veranstaltungs- und Schulungsräumen
M5.125 Absicherung der Kommunikation von und zu SAP Systemen
M5.126 Absicherung der SAP RFC-Schnittstelle
M5.127 Absicherung des SAP Internet Connection Framework (ICF)
M5.128 Absicherung der SAP ALE (IDoc/BAPI) Schnittstelle
M5.129 Sichere Konfiguration der HTTP-basierten Dienste von SAP Systemen
M5.130 Absicherung des SANs durch Segmentierung
M5.131 Absicherung von IP-Protokollen unter Windows Server 2003
M5.132 Sicherer Einsatz von WebDAV unter Windows Server 2003
M5.133 Auswahl eines VoIP-Signalisierungsprotokolls
M5.134 Sichere Signalisierung bei VoIP
M5.135 Sicherer Medientransport mit SRTP
M5.136 Dienstgüte und Netzmanagement bei VoIP
M5.137 Einsatz von NAT für VoIP
M5.138 Einsatz von RADIUS-Servern
M5.139 Sichere Anbindung eines WLANs an ein LAN
M5.140 Aufbau eines Distribution Systems
M5.141 Regelmäßige Sicherheitschecks in WLANs
M5.142 Abnahme der IT-Verkabelung
M5.143 Laufende Fortschreibung und Revision der Netzdokumentation
M5.144 Rückbau der IT-Verkabelung
M5.145 Sicherer Einsatz von CUPS
M5.146 Netztrennung beim Einsatz von Multifunktionsgeräten
M5.147 Absicherung der Kommunikation mit Verzeichnisdiensten
M5.148 Sichere Anbindung eines externen Netzes mit OpenVPN
M5.149 Sichere Anbindung eines externen Netzes mit IPSec
M5.150 Durchführung von Penetrationstests
M5.151 Sichere Konfiguration des Samba Web Administration Tools
M5.152 Austausch von Informationen und Ressourcen über\n                Peer-to-Peer-Dienste
M5.153 Planung des Netzes für virtuelle Infrastrukturen
M5.154 Sichere Konfiguration eines Netzes für virtuelle Infrastrukturen
M5.155 Datenschutz-Aspekte bei der Internet-Nutzung
M5.156 Sichere Nutzung von Twitter
M5.157 Sichere Nutzung von sozialen Netzwerken
M5.158 Nutzung von Web-Speicherplatz
M5.159 Übersicht über Protokolle und Kommunikationsstandards für\n                Webserver
M5.160 Authentisierung gegenüber Webservern
M5.161 Erstellung von dynamischen Web-Angeboten
M5.162 Planung der Leitungskapazitäten beim Einsatz von\n                Terminalservern
M5.163 Restriktive Rechtevergabe auf Terminalservern
M5.164 Sichere Nutzung eines Terminalservers aus einem entfernten\n                Netz
M5.165 Deaktivieren nicht benötigter Mac OS X-Netzdienste
M5.166 Konfiguration der Mac OS X Personal Firewall
M5.167 Sicherheit beim Fernzugriff unter Mac OS X
M5.168 Sichere Anbindung von Hintergrundsystemen an Webanwendungen\n                und Web-Services
M5.169 Systemarchitektur einer Webanwendung
M5.170 Sichere Kommunikationsverbindungen beim Einsatz von OpenLDAP
M5.171 Sichere Kommunikation zu einem zentralen\n                Protokollierungsserver
M5.172 Sichere Zeitsynchronisation bei der zentralen Protokollierung
M5.173 Nutzung von Kurz-URLs und QR-Codes
M5.174 Absicherung der Kommunikation zum Cloud-Zugriff
M5.175 Einsatz eines XML-Gateways
M5.176 Sichere Anbindung von Smartphones, Tablets und PDAs an das\n                Netz der Institution
M5.177 Serverseitige Verwendung von SSL/TLS

";

report = 'Prüfergebnisse gemäß IT-Grundschutz, 15. Ergänzungslieferung:\n\n\n';
log = string('');
ip = get_host_ip();

foreach m(massnahmen) {

  result = get_kb_item("GSHB/" + m + "/result");
  desc = get_kb_item("GSHB/" + m + "/desc");
  name = get_kb_item("GSHB/" + m + "/name");
  mn = substr(m, 0, 1);
  mz = substr(m, 3);
  sm = mn + '.' + mz + ' ';
  name = egrep(pattern:sm, string:mtitel);
  name = ereg_replace(string:name, pattern:'^M(.....)', replace:'Maßnahme \\1:');

  if(!result) {
    if(name =~ "M[45]\.... Diese Maßnahme ist entfallen!")
      result = 'Diese Maßnahme ist entfallen.';
    else if(m >!< depend)
      result = 'Prüfung dieser Maßnahme ist nicht implementierbar.';
    else
      result = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
  }

  if(!desc) {
    if(name =~ "M[45]\.... Diese Maßnahme ist entfallen!")
      desc = 'Diese Maßnahme ist entfallen.';
    else if(m >!< depend)
      desc = 'Prüfung dieser Maßnahme ist nicht implementierbar.';
    else
      desc = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
    read_desc = desc;
  } else {
    read_desc = ereg_replace(pattern:'\n', replace:'\\n', string:desc);
    read_desc = ereg_replace(pattern:'\\\\n', replace:'\\n                ', string:read_desc);
  }

  report += ' \n' + name + 'Ergebnis:       ' + result +
            '\nDetails:        ' + read_desc + '\n_______________________________________________________________________________\n';

  if(result >< 'error')
    result = 'ERR';
  else if(result >< 'Fehler')
    result = 'ERR';
  else if(result >< 'erfüllt')
    result = 'OK';
  else if(result >< 'nicht zutreffend')
    result = 'NS';
  else if(result >< 'nicht erfüllt')
    result = 'FAIL';
  else if(result >< 'unvollständig')
    result = 'NC';
  else if(result >< 'Prüfung dieser Maßnahme ist nicht implementierbar.')
    result = 'NA';
  else if(result >< 'Prüfroutine für diese Maßnahme ist nicht verfügbar.')
    result = 'NI';

  if(name =~ "M[45]\....: Diese Maßnahme ist .* entfallen")
    result = 'DEP';

  ml = mn + "." + mz;
  txt = string("'");
  log_desc = ereg_replace(pattern:'\n', replace:' ', string:desc);
  log_desc = ereg_replace(pattern:'\\\\n', replace:' ', string:log_desc);

  log += string('"' + ip + '"|"' + ml + '"|"' + result + '"|"' + log_desc + '"') + '\n';
}

format = script_get_preference("Berichtformat");
if(format == "Text" || format == "Text und Tabellarisch") {
  log_message(port:0, proto:"IT-Grundschutz", data:report);
}
if(format == "Tabellarisch" || format == "Text und Tabellarisch") {
  log_message(port:0, proto:"IT-Grundschutz-T", data:log);
}

exit(0);