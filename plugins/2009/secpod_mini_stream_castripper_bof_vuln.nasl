###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_castripper_bof_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# Mini-stream CastRipper Stack Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900651");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-22 10:20:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1667");
  script_name("Mini-stream CastRipper Stack Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35069");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8660");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8661");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8662");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_mandatory_keys("MiniStream/CastRipper/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
codes into the contenxt of the application and can crash the application.");
  script_tag(name:"affected", value:"CastRipper version 2.50.70 (2.9.6.0) and prior.
CastRipper version 2.10.00");
  script_tag(name:"insight", value:"This flaw is due to a boundary error check when processing user
supplied input data through '.M3U' files with overly long URI.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Mini-Stream CastRipper and is prone
to Stack Overflow Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

castripperVer = get_kb_item("MiniStream/CastRipper/Ver");
if(castripperVer)
{
   # Ministream CastRipper 2.50.70 points to version 2.9.6.0 & version 2.10.00
   if(version_is_less_equal(version:castripperVer, test_version:"2.9.6.0") ||
      version_is_equal(version:castripperVer, test_version:"2.10.00")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
