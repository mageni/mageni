###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blazevideo_hdtv_plf_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Blazevideo HDTV Player PLF File Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800513");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0450");
  script_bugtraq_id(33588);
  script_name("Blazevideo HDTV Player PLF File Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7975");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2009-0450");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/filedesc/blazehdtv-hof.txt.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_blazevideo_hdtv_detect.nasl");
  script_mandatory_keys("Blazevideo/HDTV/Ver");
  script_tag(name:"affected", value:"Blazevideo HDTV Player 3.5 and prior on all Windows platforms.");
  script_tag(name:"insight", value:"Player application fails while handling crafted arbitrary playlist plf files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Blazevideo HDTV Player and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary
  codes within the context of the application and can cause heap overflow
  in the application.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

blazeVer = get_kb_item("Blazevideo/HDTV/Ver");
if(blazeVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:blazeVer, test_version:"3.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
