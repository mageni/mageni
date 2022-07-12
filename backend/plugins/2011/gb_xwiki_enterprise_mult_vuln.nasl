###############################################################################
# OpenVAS Vulnerability Test
#
# XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.801841");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2010-4641", "CVE-2010-4642");
  script_bugtraq_id(44601);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42058");
  script_xref(name:"URL", value:"http://www.xwiki.org/xwiki/bin/view/ReleaseNotes/ReleaseNotesXWikiEnterprise25");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("xwiki/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code or cause SQL Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"XWiki Enterprise before 2.5.");

  script_tag(name:"insight", value:"The flaws are caused by input validation errors when processing user-supplied
  data and parameters, which could allow remote attackers to execute arbitrary
  script code or manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to XWiki Enterprise 2.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running XWiki Enterprise and is prone to unspecified
  SQL injection and cross site scripting vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);

if(ver = get_kb_item("www/" + port + "/XWiki"))
{
  if(version_is_less(version: ver, test_version: "2.5")){
    security_message(port:port);
  }
}
