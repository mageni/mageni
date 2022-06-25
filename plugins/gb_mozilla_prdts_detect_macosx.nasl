###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_detect_macosx.nasl 10467 2018-07-09 13:33:50Z cfischer $
#
# Mozilla Products Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802179");
  script_version("$Revision: 10467 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 15:33:50 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_name("Mozilla Products Version Detection (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");

  script_tag(name:"summary", value:"Detects the installed version of Mozilla products on Max OS X.

  The script logs in via ssh, searches for folder Mozilla products '.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

ffVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Firefox.app/Contents/Info CFBundleShortVersionString"));
if(strlen(ffVerCmd) > 0 && "does not exist" >!< ffVerCmd){

  ffVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:ffVerCmd);
  if(!isnull(ffVer[1])){
    if(!isnull(ffVer[2])){
      ffVer = ffVer[1] + "." + ffVer[2];
    } else {
      ffVer = ffVer[1];
    }
  }

  if(ffVer){
    key_list = make_list("/Applications/Firefox.app/Contents/MacOS", "/Applications/Firefox.app/Contents/Resources");
    foreach dir (key_list) {

      esrFile = find_file(file_name:"update-settings.ini", file_path:dir, useregex:TRUE, regexpar:"$", sock:sock);
      if(esrFile) {
        foreach binaryName (esrFile) {
          isFfEsr = get_bin_version(full_prog_name:"cat", sock:sock, version_argv:chomp(binaryName), ver_pattern:"mozilla-esr");
          if(isFfEsr) break;
        }
      }
    }

    if(isFfEsr){
      set_kb_item(name:"Mozilla/Firefox-ESR/MacOSX/Version", value:ffVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Firefox ESR", ver:ffVer, base:"cpe:/a:mozilla:firefox_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app", concluded:ffVerCmd);
    }else{
      set_kb_item(name:"Mozilla/Firefox/MacOSX/Version", value:ffVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Firefox", ver:ffVer, base:"cpe:/a:mozilla:firefox:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app", concluded:ffVerCmd);
    }
  }
}

smVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/SeaMonkey.app/Contents/Info CFBundleShortVersionString"));
if(strlen(smVerCmd) > 0 && "does not exist" >!< smVerCmd){

  smVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:smVerCmd);
  if(!isnull(smVer[1])){
    if(!isnull(smVer[2])){
      smVer = smVer[1] + "." + smVer[2];
    } else {
      smVer = smVer[1];
    }
  }

  set_kb_item(name:"SeaMonkey/MacOSX/Version", value:smVer);
  set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
  register_and_report_cpe(app:"Mozilla SeaMonkey", ver:smVer, base:"cpe:/a:mozilla:seamonkey:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/SeaMonkey.app", concluded:smVerCmd);
}

tbVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Thunderbird.app/Contents/Info CFBundleShortVersionString"));
if(strlen(tbVerCmd) > 0 && "does not exist" >!< tbVerCmd){

  tbVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:tbVerCmd);
  if(!isnull(tbVer[1])){
    if(!isnull(tbVer[2])){
      tbVer = tbVer[1] + "." + tbVer[2];
    } else {
      tbVer = tbVer[1];
    }
  }

  if(tbVer){
    dir = "/Applications/Thunderbird.app/Contents/MacOS";
    thuFile = find_file(file_name:"update-settings.ini", file_path:dir, useregex:TRUE, regexpar:"$", sock:sock);
    if(thuFile) {
      foreach binaryName (thuFile) {
        isTbEsr = get_bin_version(full_prog_name:"cat", sock:sock, version_argv:chomp(binaryName), ver_pattern:"comm-esr");
        if(isTbEsr) break;
      }
    }

    if(isTbEsr){
      set_kb_item(name:"ThunderBird-ESR/MacOSX/Version", value:tbVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Thunderbird ESR", ver:tbVer, base:"cpe:/a:mozilla:thunderbird_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app", concluded:tbVerCmd);
    }else{
      set_kb_item(name:"ThunderBird/MacOSX/Version", value:tbVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Thunderbird", ver:tbVer, base:"cpe:/a:mozilla:thunderbird:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app", concluded:tbVerCmd);
    }
  }
}

close(sock);
