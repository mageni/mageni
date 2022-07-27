###############################################################################
# OpenVAS Vulnerability Test
#
# Sympa 'sympa.pl' Insecure Temporary File Creation Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100299");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
  script_bugtraq_id(30727);
  script_cve_id("CVE-2008-4476");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Sympa 'sympa.pl' Insecure Temporary File Creation Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30727");
  script_xref(name:"URL", value:"http://www.sympa.org/");
  script_xref(name:"URL", value:"http://www.sympa.org/distribution/");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494969");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("sympa_detect.nasl");
  script_mandatory_keys("sympa/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Sympa creates temporary files in an insecure manner.");

  script_tag(name:"impact", value:"An attacker with local access could potentially exploit this issue to
  perform symbolic-link attacks, overwriting arbitrary files in the
  context of the affected application.

  Successfully mounting a symlink attack may allow the attacker to
  delete or corrupt sensitive files, which may result in a denial of
  service. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Sympa 5.4.3 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!version = get_kb_item(string("www/", port, "/sympa")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "5.4.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
