###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_mult_info_disc_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Microsoft Internet Explorer Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802286");
  script_version("$Revision: 11987 $");
  script_cve_id("CVE-2002-2435", "CVE-2010-5071");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 13:13:13 +0530 (Fri, 09 Dec 2011)");
  script_name("Microsoft Internet Explorer Multiple Information Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://w2spconf.com/2010/papers/p26.pdf");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=147777");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access
to sensitive information and launch other attacks.");
  script_tag(name:"affected", value:"Internet Explorer Version 8 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - The Cascading Style Sheets (CSS) implementation does not properly handle
the :visited pseudo-class, which allows remote attackers to obtain
sensitive  information about visited web pages via a crafted HTML document.

  - The JavaScript implementation is not properly restrict the set of values
contained in the object returned by the getComputedStyle method, which
allows remote attackers to obtain sensitive information about visited web
pages.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Internet Explorer and is prone to
multiple information disclosure vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less_equal(version:ieVer, test_version:"8.0.7600.16385")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
