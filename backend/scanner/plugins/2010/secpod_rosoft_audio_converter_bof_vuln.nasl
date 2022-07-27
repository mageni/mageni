###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rosoft_audio_converter_bof_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Rosoft Audio Converter '.M3U' file Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902079");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2329");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Rosoft Audio Converter '.M3U' file Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40195");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59483");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13895/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_rosoft_audio_converter_detect.nasl");
  script_mandatory_keys("Rosoft/Audio/Converter/Ver");
  script_tag(name:"insight", value:"The flaw exists due to boundary error when processing '.M3U' file,
which can be exploited by tricking a user into loading a specially crafted M3U file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Rosoft Audio Converter and is prone
to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Rosoft Audio Converter version 4.4.4");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

racVer = get_kb_item("Rosoft/Audio/Converter/Ver");

if(racVer != NULL)
{
  if(version_is_equal(version:racVer, test_version:"4.4.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
