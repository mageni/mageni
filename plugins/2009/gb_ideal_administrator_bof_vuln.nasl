###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ideal_administrator_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# IDEAL Administration '.ipj' File Processing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801089");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4265");
  script_name("IDEAL Administration '.ipj' File Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://freetexthost.com/abydoz3jwu");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37572");
  script_xref(name:"URL", value:"http://pocoftheday.blogspot.com/2009/12/ideal-administration-2009-v97-local.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ideal_administrator_detect.nasl");
  script_mandatory_keys("IDEAL/Admin/Ver");
  script_tag(name:"affected", value:"IDEAL Administration 9.7.1 and prior.");
  script_tag(name:"insight", value:"This flaw is due to a boundary error in the processing of Ideal Project
  Files ('.ipj'). This can be exploited to cause a stack based buffer overflow
  when a user is tricked into opening a specially crafted '.ipj' file through
  the application.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with IDEAL Administration and is prone to
  Buffer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code or
  compromise a user's system.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

if(iaVer = get_kb_item("IDEAL/Admin/Ver"))
{
  if(version_is_less_equal(version:iaVer, test_version:"9.7.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
