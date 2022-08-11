###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_mult_prdts_bof_apr09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mini-Stream Multiple Products Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900625");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1329", "CVE-2009-1328", "CVE-2009-1327",
                "CVE-2009-1326", "CVE-2009-1324", "CVE-2009-1325");
  script_bugtraq_id(34494);
  script_name("Mini-Stream Multiple Products Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34719");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34674");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8426");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8407");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49841");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49843");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");

  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
code or crash the system.");
  script_tag(name:"affected", value:"Shadow Stream Recorder version 3.0.1.7 and prior on Windows
  RM-MP3 Converter version 3.0.0.7 and prior on Windows
  WM Downloader version 3.0.0.9 and prior on Windows
  RM Downloader version 3.0.0.9 and prior on Windows
  ASXtoMP3 Converter version 3.0.0.7 and prior on Windows
  Ripper version 3.0.1.1 and prior on Windows");
  script_tag(name:"insight", value:"A boundary error occurs in multiple Mini-stream products due to
inadequate validation of user supplied data while processing playlist (.m3u)
files with overly long URI.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has Mini-Stream products installed and is prone to
Buffer Overflow Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

ssRec = get_kb_item("MiniStream/SSRecorder/Ver");
if(ssRec)
{
  if(version_is_less_equal(version:ssRec, test_version:"3.0.1.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

rmMp = get_kb_item("MiniStream/RmToMp3/Conv/Ver");
if(rmMp)
{
  if(version_is_less_equal(version:rmMp, test_version:"3.0.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

wmDown = get_kb_item("MiniStream/WMDown/Ver");
if(wmDown)
{
  if(version_is_less_equal(version:wmDown, test_version:"3.0.0.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

rmDown = get_kb_item("MiniStream/RMDown/Ver");
if(rmDown)
{
  if(version_is_less_equal(version:rmDown, test_version:"3.0.0.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

asxMp3 = get_kb_item("MiniStream/AsxToMp3/Conv/Ver");
if(asxMp3)
{
   if(version_is_less_equal(version:asxMp3, test_version:"3.0.0.7"))
   {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
   }
}

ripper = get_kb_item("MiniStream/Ripper/Ver");
if(ripper)
{
  if(version_is_less_equal(version:ripper,test_version:"3.0.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
