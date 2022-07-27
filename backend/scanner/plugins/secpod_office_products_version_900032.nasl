###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_office_products_version_900032.nasl 12513 2018-11-23 14:24:09Z cfischer $#
#
# MS Office Products Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900032");
  script_version("$Revision: 12513 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 15:24:09 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MS Office Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Retrieve the version of MS Office products
  from file and sets KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

WORDVIEW_LIST = make_list("^9\.", "cpe:/a:microsoft:office_word_viewer:2000",
                          "^10\.", "cpe:/a:microsoft:office_word_viewer:2002",
                          "^11\.", "cpe:/a:microsoft:office_word_viewer:2003",
                          "^12\.", "cpe:/a:microsoft:office_word_viewer:2007",
                          "^14\.", "cpe:/a:microsoft:office_word_viewer:2010",
                          "^15\.", "cpe:/a:microsoft:office_word_viewer:2013",
                          "^16\.", "cpe:/a:microsoft:office_word_viewer:2016");
WORDVIEW_MAX = max_index(WORDVIEW_LIST);

XLVIEW_LIST = make_list("^9\.", "cpe:/a:microsoft:office_excel_viewer:2000",
                        "^10\.", "cpe:/a:microsoft:office_excel_viewer:2002",
                        "^11\.", "cpe:/a:microsoft:office_excel_viewer:2003",
                        "^12\.", "cpe:/a:microsoft:office_excel_viewer:2007",
                        "^14\.", "cpe:/a:microsoft:office_excel_viewer:2010",
                        "^15\.", "cpe:/a:microsoft:office_excel_viewer:2013",
                        "^16\.", "cpe:/a:microsoft:office_excel_viewer:2016");
XLVIEW_MAX = max_index(XLVIEW_LIST);

PPVIEW_LIST = make_list("^9\.", "cpe:/a:microsoft:office_powerpoint_viewer:2000",
                        "^10\.", "cpe:/a:microsoft:office_powerpoint_viewer:2002",
                        "^11\.", "cpe:/a:microsoft:office_powerpoint_viewer:2003",
                        "^12\.", "cpe:/a:microsoft:office_powerpoint_viewer:2007",
                        "^14\.", "cpe:/a:microsoft:office_powerpoint_viewer:2010",
                        "^15\.", "cpe:/a:microsoft:office_powerpoint_viewer:2013",
                        "^16\.", "cpe:/a:microsoft:office_powerpoint_viewer:2016");
PPVIEW_MAX = max_index(PPVIEW_LIST);

VISIO_LIST = make_list("^9\.", "cpe:/a:microsoft:visio_viewer:2000",
                       "^10\.", "cpe:/a:microsoft:visio_viewer:2002",
                       "^11\.", "cpe:/a:microsoft:visio_viewer:2003",
                       "^12\.", "cpe:/a:microsoft:visio_viewer:2007",
                       "^14\.", "cpe:/a:microsoft:visio_viewer:2010",
                       "^15\.", "cpe:/a:microsoft:visio_viewer:2013",
                       "^16\.", "cpe:/a:microsoft:visio_viewer:2016");
VISIO_MAX = max_index(VISIO_LIST);

WORD_LIST = make_list("^9\.", "cpe:/a:microsoft:office_word:2000",
                      "^10\.", "cpe:/a:microsoft:office_word:2002",
                      "^11\.", "cpe:/a:microsoft:office_word:2003",
                      "^12\.", "cpe:/a:microsoft:office_word:2007",
                      "^14\.", "cpe:/a:microsoft:office_word:2010",
                      "^15\.", "cpe:/a:microsoft:office_word:2013",
                      "^16\.", "cpe:/a:microsoft:office_word:2016");
WORD_MAX = max_index(WORD_LIST);

EXCEL_LIST = make_list("^9\.", "cpe:/a:microsoft:office_excel:2000",
                       "^10\.", "cpe:/a:microsoft:office_excel:2002",
                       "^11\.", "cpe:/a:microsoft:office_excel:2003",
                       "^12\.", "cpe:/a:microsoft:office_excel:2007",
                       "^14\.", "cpe:/a:microsoft:office_excel:2010",
                       "^15\.", "cpe:/a:microsoft:office_excel:2013",
                       "^16\.", "cpe:/a:microsoft:office_excel:2016");
EXCEL_MAX = max_index(EXCEL_LIST);

ACCESS_LIST = make_list("^9\.", "cpe:/a:microsoft:access:2000",
                        "^10\.", "cpe:/a:microsoft:access:2002",
                        "^11\.", "cpe:/a:microsoft:access:2003",
                        "^12\.", "cpe:/a:microsoft:access:2007",
                        "^14\.", "cpe:/a:microsoft:access:2010",
                        "^15\.", "cpe:/a:microsoft:access:2013",
                        "^16\.", "cpe:/a:microsoft:access:2016");
ACCESS_MAX = max_index(ACCESS_LIST);

POWERPNT_LIST = make_list("^9\.", "cpe:/a:microsoft:office_powerpoint:2000",
                          "^10\.", "cpe:/a:microsoft:office_powerpoint:2002",
                          "^11\.", "cpe:/a:microsoft:office_powerpoint:2003",
                          "^12\.", "cpe:/a:microsoft:office_powerpoint:2007",
                          "^14\.", "cpe:/a:microsoft:office_powerpoint:2010",
                          "^15\.", "cpe:/a:microsoft:office_powerpoint:2013",
                          "^16\.", "cpe:/a:microsoft:office_powerpoint:2016");
POWERPNT_MAX = max_index(POWERPNT_LIST);

OUTLOOK_LIST = make_list("^9\.", "cpe:/a:microsoft:outlook:2000",
                         "^10\.", "cpe:/a:microsoft:outlook:2002",
                         "^11\.", "cpe:/a:microsoft:outlook:2003",
                         "^12\.", "cpe:/a:microsoft:outlook:2007",
                         "^14\.", "cpe:/a:microsoft:outlook:2010",
                         "^15\.", "cpe:/a:microsoft:outlook:2013",
                         "^16\.", "cpe:/a:microsoft:outlook:2016");
OUTLOOK_MAX = max_index(OUTLOOK_LIST);

PUBLISHER_LIST = make_list("^9\.", "cpe:/a:microsoft:office_publisher:2000",
                           "^10\.", "cpe:/a:microsoft:office_publisher:2002",
                           "^11\.", "cpe:/a:microsoft:office_publisher:2003",
                           "^12\.", "cpe:/a:microsoft:office_publisher:2007",
                           "^14\.", "cpe:/a:microsoft:office_publisher:2010",
                           "^15\.", "cpe:/a:microsoft:office_publisher:2013",
                           "^16\.", "cpe:/a:microsoft:office_publisher:2016");
PUBLISHER_MAX = max_index(PUBLISHER_LIST);

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  exit(0);
}

# Word Viewer
wordviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wordview.exe", item:"Path");
if(wordviewFile)
{
  set_kb_item(name:"SMB/Office/WordView/Install/Path", value:wordviewFile);
  set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

  wordviewFile += "\WORDVIEW.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordviewFile);
  wview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordviewFile);
  wordviewVer = GetVer(file:wview, share:share);
  if(wordviewVer){
    set_kb_item(name:"SMB/Office/WordView/Version", value:wordviewVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < WORDVIEW_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:wordviewVer, pattern:WORDVIEW_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office WordView", ver:wordviewVer, insloc:wordviewFile,
                                base:WORDVIEW_LIST[i+1], expr:WORDVIEW_LIST[i]);
        break;
      }
    }
  }
}

# Excel Viewer (or) PowerPoint Viewer (or) Office Compatibility Pack
## For 32-bit application on 64-bit OS, added support
key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                     "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    if("Microsoft Office Excel Viewer" >< registry_get_sz(key:key + item, item:"DisplayName"))
    {
      xlviewVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(xlviewVer != NULL)
      {
        if("Wow6432Node" >< key ) {
          xlviewFile = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
        } else {
          xlviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
        }

        if(xlviewVer =~ "^11\.")
          xlviewFile += "\Microsoft Office\Office11\XLVIEW.EXE";
        else if(xlviewVer =~ "^12\.")
          xlviewFile += "\Microsoft Office\Office12\XLVIEW.EXE";
        else if(xlviewVer =~ "^14\.")
           xlviewFile += "\Microsoft Office\Office14\XLVIEW.EXE";
        else if(xlviewVer =~ "^15\.")
           xlviewFile += "\Microsoft Office\Office15\XLVIEW.EXE";
        else if(xlviewVer =~ "^16\.")
           xlviewFile += "\Microsoft Office\Office16\XLVIEW.EXE";

        if(xlviewFile != NULL)
        {
          share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:xlviewFile);
          xlview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:xlviewFile);
          xlviewVer = GetVer(file:xlview, share:share);
          if(xlviewVer != NULL){
            set_kb_item(name:"SMB/Office/XLView/Version", value:xlviewVer);
            set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

            for (i = 0; i < XLVIEW_MAX-1; i = i + 2) {
              # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
              if( egrep( string:xlviewVer, pattern:XLVIEW_LIST[i] ) ) {
                register_and_report_cpe(app:"Microsoft Office Excel Viewer", ver:xlviewVer, insloc:xlviewFile,
                                        base:XLVIEW_LIST[i+1], expr:XLVIEW_LIST[i]);
                break;
              }
            }
          }
        }
      }
    }
    if("Microsoft Office PowerPoint Viewer" >< registry_get_sz(key:key + item, item:"DisplayName")||
       "Microsoft PowerPoint Viewer" >< registry_get_sz(key:key + item, item:"DisplayName"))
    {
      pptviewVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(pptviewVer != NULL)
      {
        if("Wow6432Node" >< key ) {
          ppviewFile = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
        } else {
          ppviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
        }

        if(pptviewVer =~ "^11\.")
          ppviewFile += "\Microsoft Office\PowerPoint Viewer\PPTVIEW.exe";
        else if(pptviewVer =~ "^12\.")
          ppviewFile += "\Microsoft Office\Office12\PPTVIEW.exe";
        else if (pptviewVer =~ "^14\.")
          ppviewFile += "\Microsoft Office\Office14\PPTVIEW.exe";
        else if (pptviewVer =~ "^15\.")
          ppviewFile += "\Microsoft Office\Office15\PPTVIEW.exe";
        else if (pptviewVer =~ "^16\.")
          ppviewFile += "\Microsoft Office\Office16\PPTVIEW.exe";

        if(ppviewFile != NULL)
        {
          share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppviewFile);
          pptview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppviewFile);
          pptviewVer = GetVer(file:pptview, share:share);
          if(pptviewVer != NULL){
            set_kb_item(name:"SMB/Office/PPView/Version", value:pptviewVer);
            set_kb_item(name:"SMB/Office/PPView/FilePath", value:ppviewFile);
            set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

            for (i = 0; i < PPVIEW_MAX-1; i = i + 2) {
              # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
              if( egrep( string:pptviewVer, pattern:PPVIEW_LIST[i] ) ) {
                register_and_report_cpe(app:"Microsoft PowerPoint Viewer", ver:pptviewVer, insloc:ppviewFile,
                                        base:PPVIEW_LIST[i+1], expr:PPVIEW_LIST[i]);
                break;
              }
            }
          }
        }
      }
    }
    if("Compatibility Pack" >< registry_get_sz(key:key + item, item:"DisplayName"))
    {
      cPackVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(cPackVer != NULL){
        set_kb_item(name:"SMB/Office/ComptPack/Version", value:cPackVer);
        set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

        # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
        if( cPackVer =~ "^12\." ) {
          register_and_report_cpe(app:"Microsoft Office Compatibility Pack", ver:cPackVer,
                                  base:"cpe:/a:microsoft:compatibility_pack_word_excel_powerpoint:2007:", expr:"^(12\..*)");
        }
      }
    }
  }
}

# Office Groove
groovePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\GROOVE.EXE", item:"Path");
if(groovePath != NULL)
{
  groovePath += "\GROOVE.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:groovePath);
  groove = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:groovePath);
  grooveVer = GetVer(file:groove, share:share);
  if(grooveVer != NULL){
    set_kb_item(name:"SMB/Office/Groove/Version", value:grooveVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
    if( grooveVer =~ "^12\." ) {
      register_and_report_cpe(app:"Microsoft Office Groove", ver:grooveVer, insloc:groovePath,
                              base:"cpe:/a:microsoft:office_groove:2007:", expr:"^(12\..*)");
    }
  }
}

# Office Power Point Convertes
ppcnvFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(ppcnvFile)
{
  ppcnvFile += "\Microsoft Office\Office12\PPCNVCOM.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppcnvFile);
  ppfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppcnvFile);
  ppcnvVer = GetVer(file:ppfile, share:share);
  if(ppcnvVer){
    set_kb_item(name:"SMB/Office/PowerPntCnv/Version", value:ppcnvVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
    if( ppcnvVer =~ "^12\.)" ) {
      ##Need to update base value
      register_and_report_cpe(app:"Microsoft Office Power Point", ver:ppcnvVer, insloc:ppcnvFile,
                              base:"", expr:"^(12\..)*");
    }
  }
}

# Office Visio Viewer
visioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
visioPath1 = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(visioPath || visioPath1)
{
  foreach path (make_list("Office12", "Office14", "Office15", "Office16"))
  {
    exePath = visioPath + "\Microsoft Office\" + path;
    visiovVer = fetch_file_version(sysPath:exePath, file_name:"Vpreview.exe");
    if(!visiovVer) {
      exePath = visioPath1 + "\Microsoft Office\" + path;
      visiovVer = fetch_file_version(sysPath:exePath, file_name:"Vpreview.exe");
    }
    if(visiovVer)
    {
      set_kb_item(name:"SMB/Office/VisioViewer/Path", value:exePath);
      set_kb_item(name:"SMB/Office/VisioViewer/Ver", value:visiovVer);
      set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

      for (i = 0; i < VISIO_MAX-1; i = i + 2) {
        # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
        if( egrep( string:visiovVer, pattern:VISIO_LIST[i] ) ) {
          register_and_report_cpe(app:"Microsoft Office VisioViewer", ver:visiovVer, insloc:exePath + "\Vpreview.exe",
                                  base:VISIO_LIST[i+1], expr:VISIO_LIST[i]);
          break;
        }
      }
    }
  }
}

# To Conform Office Installation
if(!get_kb_item("MS/Office/Ver")){
  exit(0);
}

# Office Word
wordFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Winword.exe", item:"Path");
if(wordFile)
{
  set_kb_item(name:"SMB/Office/Word/Install/Path", value:wordFile);
  set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

  wordFile += "\winword.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordFile);
  word = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordFile);
  wordVer = GetVer(file:word, share:share);
  if(wordVer){
    set_kb_item(name:"SMB/Office/Word/Version", value:wordVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < WORD_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:wordVer, pattern:WORD_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office Word", ver:wordVer, insloc:wordFile,
                                base:WORD_LIST[i+1], expr:WORD_LIST[i]);
        break;
      }
    }
  }
}

# Office Excel
excelFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Excel.exe", item:"Path");
if(excelFile)
{
  set_kb_item(name:"SMB/Office/Excel/Install/Path", value:excelFile);
  set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

  excelFile += "\excel.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:excelFile);
  excel =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:excelFile);
  excelVer = GetVer(file:excel, share:share);
  if(excelVer){
    set_kb_item(name:"SMB/Office/Excel/Version", value:excelVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < EXCEL_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:excelVer, pattern:EXCEL_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office Excel", ver:excelVer, insloc:excelFile,
                                base:EXCEL_LIST[i+1], expr:EXCEL_LIST[i]);
        break;
      }
    }
  }
}

# Office Access
accessFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\MSACCESS.exe", item:"Path");
if(accessFile)
{
  accessFile += "\msaccess.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:accessFile);
  access = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:accessFile);
  accessVer = GetVer(file:access, share:share);
  if(accessVer){
    set_kb_item(name:"SMB/Office/Access/Version", value:accessVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < ACCESS_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:accessVer, pattern:ACCESS_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office Access", ver:accessVer, insloc:accessFile,
                                base:ACCESS_LIST[i+1], expr:ACCESS_LIST[i]);
        break;
      }
    }
  }
}

# Office PowerPoint
powerpointFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\PowerPnt.exe", item:"Path");
if(powerpointFile)
{
  powerpointFile += "\powerpnt.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:powerpointFile);
  power = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:powerpointFile);
  powerPptVer = GetVer(file:power, share:share);
  if(powerPptVer){
    set_kb_item(name:"SMB/Office/PowerPnt/Version", value:powerPptVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < POWERPNT_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:powerPptVer, pattern:POWERPNT_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office PowerPoint", ver:powerPptVer, insloc:powerpointFile,
                                base:POWERPNT_LIST[i+1], expr:POWERPNT_LIST[i]);
        break;
      }
    }
  }
}

# Office Word Converter
wordcnvFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(wordcnvFile)
{
  wordcnvFile += "\Microsoft Office\Office12\Wordconv.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordcnvFile);
  word  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordcnvFile);
  wordcnvVer = GetVer(file:word, share:share);
  if(wordcnvVer){
    set_kb_item(name:"SMB/Office/WordCnv/Version", value:wordcnvVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
    if( wordcnvVer =~ "^12\." ) {
      ## Add BASE Value
      register_and_report_cpe(app:"Microsoft Office Word Converter", ver:wordcnvVer, insloc:wordcnvFile,
                              base:"", expr:"^(12\..*)");
    }
  }
}

# Office Excel Converter
xlcnvFile1 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
xlcnvFile2 = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");

if(xlcnvFile1 || xlcnvFile2)
{
  xlcnvFile += "\Microsoft Office\Office12\excelcnv.exe";
  xlcnvPath = xlcnvFile1 + "\Microsoft Office\Office12\";
  xlcnvVer = fetch_file_version(sysPath:xlcnvPath, file_name:"excelcnv.exe");
  if(!xlcnvVer) {
    xlcnvPath = xlcnvFile2 + "\Microsoft Office\Office12\";
    xlcnvVer = fetch_file_version(sysPath:xlcnvPath, file_name:"excelcnv.exe");
  }
  if(xlcnvVer){
    set_kb_item(name:"SMB/Office/XLCnv/Version", value:xlcnvVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
    if( xlcnvVer =~ "^12\." ) {
      ## Add BASE Value
      register_and_report_cpe(app:"Microsoft Office Excel Converter", ver:xlcnvVer, insloc:xlcnvFile,
                              base:"", expr:"^(12\..*)");
    }
  }
}

# Office Publisher
pubFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\MSPUB.EXE", item:"Path");
if(pubFile)
{
  set_kb_item(name:"SMB/Office/Publisher/Installed/Path", value:pubFile);
  set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pubFile);
  pub = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:pubFile + "\MSPUB.exe");
  pubVer = GetVer(file:pub, share:share);
  if(pubVer){
    set_kb_item(name:"SMB/Office/Publisher/Version", value:pubVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < PUBLISHER_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:pubVer, pattern:PUBLISHER_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office Publisher", ver:pubVer, insloc:pubFile + "\MSPUB.exe",
                                base:PUBLISHER_LIST[i+1], expr:PUBLISHER_LIST[i]);
        break;
      }
    }
  }
}

# Office outlook
outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE", item:"Path");
if(outlookFile)
{
  set_kb_item(name:"SMB/Office/Outlook/Install/Path", value:outlookFile);

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:outlookFile);
  outlook = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:outlookFile + "\OUTLOOK.EXE");
  outlookVer = GetVer(file:outlook, share:share);
  if(outlookVer){
    set_kb_item(name:"SMB/Office/Outlook/Version", value:outlookVer);
    set_kb_item(name:"MS/Office/Prdts/Installed", value:TRUE);

    for (i = 0; i < OUTLOOK_MAX-1; i = i + 2) {
      # Special handling as register_and_report_cpe would register the product without a version if the expr doesn't match
      if( egrep( string:outlookVer, pattern:OUTLOOK_LIST[i] ) ) {
        register_and_report_cpe(app:"Microsoft Office Outlook", ver:outlookVer, insloc:outlookFile + "\OUTLOOK.EXE",
                                base:OUTLOOK_LIST[i+1], expr:OUTLOOK_LIST[i]);
        break;
      }
    }
  }
}
