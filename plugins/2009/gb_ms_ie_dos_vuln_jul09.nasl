###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_dos_vuln_jul09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Microsoft Internet Explorer Denial Of Service Vulnerability - July09
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
  script_oid("1.3.6.1.4.1.25623.1.0.800669");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2536", "CVE-2009-1692");
  script_bugtraq_id(35446);
  script_name("Microsoft Internet Explorer Denial Of Service Vulnerability - July09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9160");
  script_xref(name:"URL", value:"http://www.g-sec.lu/one-bug-to-rule-them-all.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of
  service by exhausting memory.");
  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x and 8.x");
  script_tag(name:"insight", value:"Error exists while calling the select method with a large
  integer, that results in continuos allocation of x+n bytes of memory exhausting
  memory after a while.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Internet Explorer and is prone to
  Denial Of Service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("version_func.inc");

if(!ieVer = get_kb_item("MS/IE/Version")) exit(0);

if(version_in_range(version:ieVer, test_version:"5.0",
                                   test_version2:"8.0.6001.18702")){
  report = report_fixed_ver(installed_version:ieVer, fixed_version:"N/A");
  security_message(data:report);
  exit(0);
}

exit(99);