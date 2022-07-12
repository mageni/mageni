###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mini_stream_ripper_and_rmmp3_conv_bof_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Mini-Stream Ripper And RM-MP3 Converter '.pls' File Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012  Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802368");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2009-5109", "CVE-2010-5081");
  script_bugtraq_id(41332, 34514);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-03 10:37:57 +0530 (Tue, 03 Jan 2012)");
  script_name("Mini-Stream Ripper And RM-MP3 Converter '.pls' File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://sebug.net/vuldb/ssvid-18793");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18082");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10782");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10747");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10745");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18113");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14373");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_mandatory_keys("MiniStream/Products/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of
arbitrary code.");
  script_tag(name:"affected", value:"Ripper version 3.0.1.1 and prior
RM-MP3 Converter version 3.1.2.1");
  script_tag(name:"insight", value:"The flaw is due to an error when processing '.pls' files, which
can be exploited to cause a stack based buffer overflow by sending specially
crafted '.pls' file with a long entry.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Mini-Stream Ripper or RM-MP3
Converter and is prone to buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

rmMp3 = get_kb_item("MiniStream/RmToMp3/Conv/Ver");
if(rmMp3)
{
  #Mini-stream RM-MP3 Converter 3.1.2.1 points to version 3.1.2.1.2010.03.30
  if(version_is_equal(version:rmMp3, test_version:"3.1.2.1.2010.03.30"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

miniRipper = get_kb_item("MiniStream/Ripper/Ver");
if(miniRipper)
{
  if(version_is_less_equal(version:miniRipper,test_version:"3.0.1.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
