###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_135.nasl 13069 2019-01-14 15:33:06Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.135
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94215");
  script_version("$Revision: 13069 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-14 16:33:06 +0100 (Mon, 14 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_SSH_sys_dir_write_perm.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SMB_SDDL.nasl");
  script_require_keys("GSHB/ROOTSDDL");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04135.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("itg.inc");
include("wmi_misc.inc");

name = 'IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien\n';
gshbm =  "IT-Grundschutz M4.135: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WindowsDomain = get_kb_item("WMI/WMI_WindowsDomain");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
WINSDDL = get_kb_item("GSHB/WINSDDL");
ROOTSDDL = get_kb_item("GSHB/ROOTSDDL");
log = get_kb_item("WMI/WMI_OS/log");
log += '\n' + get_kb_item("GSHB/WINSDDL/log");
stat =  get_kb_item("GSHB/WINSDDL/stat");
Writeperm = get_kb_item("GSHB/Dir-Writeperm");
Writepermlog = get_kb_item("GSHB/Dir-Writeperm/log");

if(OSVER >!< "none" && stat){

  DEFINITION = "ace_type:ace_flags:rights:object_guid:inherit_object_guid:account_sid";
  VAL_ROOTSDDL = ereg_replace(pattern:"(\)\()", string:ROOTSDDL, replace:'|');
  VAL_ROOTSDDL = ereg_replace(pattern:"(\))", string:VAL_ROOTSDDL, replace:'|');
  VAL_ROOTSDDL = ereg_replace(pattern:"(\()", string:VAL_ROOTSDDL, replace:'|');
  SPL_ROOTSDDL = split(VAL_ROOTSDDL, sep:"|", keep:FALSE);

  sid_codes = get_wmi_misc_sid_codes();
  ace_types = get_wmi_misc_ace_types();
  ace_flags = get_wmi_misc_ace_flags();
  ace_access_mask = get_wmi_misc_ace_access_mask();
  access_mask_hex = get_wmi_misc_access_mask_hex();

  for(i=1; i<max_index(SPL_ROOTSDDL); i++){

    SPLROOTSDDL = split(SPL_ROOTSDDL[i], sep:";", keep:FALSE);

    for(A = 0; A >= 0; A++)
    {
      if(isnull(ace_types[A]))
        break;

      if(ace_types[A] == SPLROOTSDDL[0])
        ACE = ace_types[A + 1];
    }

    ACEFLAG = NULL;
    for(B = 0; B >= 0; B++)
    {
      if(isnull(ace_flags[B]))
        break;

      aceflaglength = strlen(SPLROOTSDDL[1]);
      if(ace_flags[B] >< SPLROOTSDDL[1] && aceflaglength == 2)
        ACEFLAG = ace_flags[B + 1];
      else if(ace_flags[B] >< SPLROOTSDDL[1] && aceflaglength > 2){
        if (!ACEFLAG)
          ACEFLAG = ace_flags[B + 1];
        else
          ACEFLAG += "/" + ace_flags[B + 1];
      }
    }

    ACM = NULL;
    if (SPLROOTSDDL[2] =~ "0x(.*){8}")
    {
      for(C = 0; C >= 0; C++)
      {
        if(isnull(access_mask_hex[C]))
          break;

        ACMH_val = split(SPLROOTSDDL[2], sep:"x", keep:FALSE);
        ACM_hex = toupper(ACMH_val[1]);
        ACM_hex = "0x" + ACM_hex;
        if(access_mask_hex[C] >< ACM_hex)
          ACM = access_mask_hex[C + 1];
        if (!ACM) ACM = ACM_hex;
      }
   }
   else
   {
     for(C = 0; C >= 0; C++)
     {
       if(isnull(ace_access_mask[C]))
         break;

        acemasklength = strlen(SPLROOTSDDL[2]);
        if(ace_access_mask[C] >< SPLROOTSDDL[2] && acemasklength == 2)
          ACM = ace_access_mask[C + 1];
        else if(ace_access_mask[C] >< SPLROOTSDDL[2] && acemasklength > 2){
          if (!ACM)
            ACM = ace_access_mask[C + 1];
          else
            ACM += "/" + ace_access_mask[C + 1];
        }
      }
    }

    for(D = 0; D >= 0; D++)
    {
      if(isnull(sid_codes[D]))
        break;

      if(sid_codes[D] == SPLROOTSDDL[5])
        SID = sid_codes[D + 1];
    }
    ROOTFULLACE +=  ACE + ":" + ACEFLAG +  ":" + ACM + ":::" + SID + '\n';
  }

  VAL_WINSDDL = ereg_replace(pattern:"(\)\()", string:WINSDDL, replace:'|');
  VAL_WINSDDL = ereg_replace(pattern:"(\))", string:VAL_WINSDDL, replace:'|');
  VAL_WINSDDL = ereg_replace(pattern:"(\()", string:VAL_WINSDDL, replace:'|');
  SPL_WINSDDL = split(VAL_WINSDDL, sep:"|", keep:FALSE);

  for(i=1; i<max_index(SPL_WINSDDL); i++){

    SPLWINSDDL = split(SPL_WINSDDL[i], sep:";", keep:FALSE);

    for(A = 0; A >= 0; A++)
    {
      if(isnull(ace_types[A]))
        break;

      if(ace_types[A] == SPLWINSDDL[0])
        ACE = ace_types[A + 1];
    }

    ACEFLAG = NULL;
    for(B = 0; B >= 0; B++)
    {
      if(isnull(ace_flags[B]))
        break;

      aceflaglength = strlen(SPLWINSDDL[1]);
      if(ace_flags[B] >< SPLWINSDDL[1] && aceflaglength == 2)
        ACEFLAG = ace_flags[B + 1] + ":";
      else if(ace_flags[B] >< SPLWINSDDL[1] && aceflaglength > 2){
        if (!ACEFLAG)
          ACEFLAG = ace_flags[B + 1];
        else
          ACEFLAG += "/" + ace_flags[B + 1];
      }
    }

    ACM = NULL;
    if (SPLWINSDDL[2] =~ "0x(.*){8}")
    {
      for(C = 0; C >= 0; C++)
      {
        if(isnull(access_mask_hex[C]))
          break;

        ACMH_val = split(SPLWINSDDL[2], sep:"x", keep:FALSE);
        ACM_hex = toupper(ACMH_val[1]);
        ACM_hex = "0x" + ACM_hex;
        if(access_mask_hex[C] >< ACM_hex)
          ACM = access_mask_hex[C + 1];
          if (!ACM) ACM = ACM_hex;
      }
    }
    else
    {
      for(C = 0; C >= 0; C++)
      {
        if(isnull(ace_access_mask[C]))
          break;

        acemasklength = strlen(SPLWINSDDL[2]);
        if(ace_access_mask[C] >< SPLWINSDDL[2] && acemasklength == 2)
          ACM = ace_access_mask[C + 1];
        else if(ace_access_mask[C] >< SPLWINSDDL[2] && acemasklength > 2){
          if (!ACM)
            ACM = ace_access_mask[C + 1];
          else
            ACM += "/" + ace_access_mask[C + 1];
        }
      }
    }

    for(D = 0; D >= 0; D++)
    {
      if(isnull(sid_codes[D]))
        break;

      if(sid_codes[D] == SPLWINSDDL[5])
        SID = sid_codes[D + 1];
    }
    WINFULLACE +=  ACE + ":" + ACEFLAG +  ":" + ACM + ":::" + SID + '\n';
  }

  if(OSVER >< "error" || WINSDDL >< "error"){
    result = string("Fehler");
    if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }
  #nb: Windows 2000 und kleiner:
  else if(OSVER <= '5.0')
  {
    result = string("unvollst‰ndig");
    desc = string("Ungepr¸ft");
  }

  #nb: Windows XP und 2003:
  else if(OSVER > '5.0' && OSVER < '6.0' && OSTYPE != 2)
  {
    if (ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und f¸r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL != "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f¸r das Systemlaufwerk wurden ge‰ndert.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL != "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf¸r das Windows-Verzeichnis wurden ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("unvollst‰ndig");
      desc = string('F¸r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge‰ndert. Sie entsprechen\nnicht mehr den Default-Einstellungen. Bitte ¸berpr¸fen\nSie die Sicherheitseinstellungen und passen sie diese\nggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #nb: Windows 2003 Domaincontroller:
  else if(OSVER == '5.2' && OSTYPE == 2 )
  {
    if (ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und f¸r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL != "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f¸r das Systemlaufwerk wurden ge‰ndert.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL != "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf¸r das Windows-Verzeichnis wurden ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("unvollst‰ndig");
      desc = string('F¸r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge‰ndert. Sie entsprechen\nnicht mehr den Default-Einstellungen. Bitte ¸berpr¸fen\nSie die Sicherheitseinstellungen und passen sie diese\nggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #nb: Vista und Windows 7
  else if(OSVER >= '6.0' && OSTYPE == 1)
  {
    if (ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und f¸r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f¸r das Systemlaufwerk wurden ge‰ndert.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf¸r das Windows-Verzeichnis wurden ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #nb: Windows 2008 und 2008 R2 NON Domaincontroller
  else if(OSVER >= '6.0' && OSTYPE == 3)
  {
    if (ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und f¸r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f¸r das Systemlaufwerk wurden ge‰ndert.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf¸r das Windows-Verzeichnis wurden ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #nb: Windows 2008 und 2008 R2 Domaincontroller
  else if(OSVER >= '6.0' && OSTYPE == 2)
  {
    if (ROOTSDDL == "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und f¸r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL != "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("unvollst‰ndig");
      desc = string('F¸r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f¸r das Systemlaufwerk wurden ge‰ndert.\nBitte ¸berpr¸fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else if(ROOTSDDL == "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf¸r das Windows-Verzeichnis wurden ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf¸llt");
      desc = string('F¸r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge‰ndert. Bitte\n¸berpr¸fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }
}else{
  if(!stat){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine File and Folder ACL abgerufen werden.");
  }else if(Writeperm >< "error"){
    result = string("Fehler");
    if (!Writepermlog)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf.');
    if (Writepermlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
  }else if(Writeperm >< "none"){
    result = string("erf¸llt");
    desc = string('Es wurden, ausgenommen von /home/* und /tmp/*, keine\nVerzeichnisse mit Schreibrecht f¸r Benutzer gefunden.');
  }else if(Writeperm == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnten die Sicherheitseinstellungen der\nVerzeichnisse nicht gelesen werden. Folgende Fehler\nsind aufgetreten:\n' + log);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnten die Sicherheitseinstellungen der\nVerzeichnisse nicht gelesen werden. Folgende Fehler\nsind aufgetreten:\n' + log);
  }else if(Writeperm >< "nofind") {
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde der Befehl -find-\nnicht gefunden.');
  }else{
    result = string("nicht erf¸llt");
    desc = string('Es wurden, ausgenommen von /home/* und /tmp/*,\nfolgende Verzeichnisse mit Schreibrecht f¸r Benutzer\ngefunden:\n' + Writeperm);
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_135/result", value:result);
set_kb_item(name:"GSHB/M4_135/desc", value:desc);
set_kb_item(name:"GSHB/M4_135/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_135');

exit(0);