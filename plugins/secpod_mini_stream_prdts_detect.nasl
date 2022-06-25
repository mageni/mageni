###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_prdts_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Mini-Stream Products Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-03-31
#  - Modified regex to detect the recent versions of rm downloader
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900624");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mini-Stream Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"The script will detect the Mini-Stream products installed on
  this host and set the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

item1 = "Shadow Stream Recorder_is1\";
ssRecName = registry_get_sz(key:key+item1, item:"DisplayName");
ssRVer = eregmatch(pattern:"Recorder ([0-9.]+)", string:ssRecName);

if(ssRVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  set_kb_item(name:"MiniStream/SSRecorder/Ver", value:ssRVer[1]);
  register_and_report_cpe(app:ssRecName, ver:ssRVer[1], base:"cpe:/a:mini-stream:shadow_stream_recorder:",
                          expr:"^([0-9.]+)");
}

item2 = "Mini-stream RM-MP3 Converter_is1\";
rmTmp = registry_get_sz(key:key+item2, item:"DisplayName");
rmTmpVer = eregmatch(pattern:"Converter ([0-9]\.[0-9]\.[0-9.]+)", string:rmTmp);

if(rmTmpVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  set_kb_item(name:"MiniStream/RmToMp3/Conv/Ver", value:rmTmpVer[1]);
  register_and_report_cpe(app:rmTmp, ver:rmTmpVer[1], base:"cpe:/a:mini-stream:easy_rm-mp3_converter:",
                          expr:"^([0-9.]+)");
}

item3 = "WM Downloader_is1\";
wmDown = registry_get_sz(key:key+item3, item:"DisplayName");
wmDownVer = eregmatch(pattern:"Converter ([0-9.]+)", string:wmDown);

if(wmDownVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  set_kb_item(name:"MiniStream/WMDown/Ver", value:wmDownVer[1]);
  register_and_report_cpe(app:wmDown, ver:wmDownVer[1], base:"cpe:/a:mini-stream:wm_downloader:",
                          expr:"^([0-9.]+)");
}

item4 = "RM Downloader_is1\";
rmDown = registry_get_sz(key:key+item4, item:"DisplayName");
rmDownVer = eregmatch(pattern:" Downloader(..([0-9.]+))", string:rmDown);
if(rmDownVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  rmDownVer = ereg_replace(pattern:" ", string:rmDownVer[1], replace:"");
  set_kb_item(name:"MiniStream/RMDown/Ver", value:rmDownVer);
  register_and_report_cpe(app:rmDown, ver:rmDownVer[1], base:"cpe:/a:mini-stream:mini-stream_rm_downloader:",
                               expr:"^([0-9.]+)");
}

item5 = "ASX to MP3 Converter_is1\";
asx2mpName= registry_get_sz(key:key+item5, item:"DisplayName");
asx2mpVer = eregmatch(pattern:"Converter ([0-9]\.[0-9]\.[0-9.]+)", string:asx2mpName);

if(asx2mpVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  set_kb_item(name:"MiniStream/AsxToMp3/Conv/Ver", value:asx2mpVer[1]);
  register_and_report_cpe(app:asx2mpName, ver:asx2mpVer[1], base:"cpe:/a:mini-stream:mini-stream_to_mp3_converter:",
                          expr:"^([0-9.]+)");
}

item6 = "Mini-stream Ripper_is1\";
msRipper = registry_get_sz(key:key+item6, item:"DisplayName");
msRipperVer = eregmatch(pattern:"Ripper ([0-9.]+)", string:msRipper);

if(msRipperVer[1]!=NULL)
{
  set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
  set_kb_item(name:"MiniStream/Ripper/Ver", value:msRipperVer[1]);
  register_and_report_cpe(app:msRipper, ver:msRipperVer[1], base:"cpe:/a:mini-stream:ripper:",
                          expr:"^([0-9.]+)");
}


item7 = "CastRipper_is1\";
nameRipper = registry_get_sz(key:key+item7, item:"Publisher");
if("Mini-stream" >< nameRipper)
{
  castripperVer = registry_get_sz(key:key+item7, item:"DisplayName");
  castripperVer = eregmatch(pattern:"CastRipper ([0-9.]+)", string:castripperVer);

  if(castripperVer[1] != NULL){
    set_kb_item(name:"MiniStream/Products/Installed", value:TRUE);
    set_kb_item(name:"MiniStream/CastRipper/Ver", value:castripperVer[1]);
    register_and_report_cpe(app:nameRipper, ver:castripperVer[1], base:"cpe:/a:mini-stream:castripper:",
                            expr:"^([0-9.]+)");
  }
}
exit(0);
