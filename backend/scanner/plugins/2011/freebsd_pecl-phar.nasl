###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_pecl-phar.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Auto generated from VID da3d381b-0ee6-11e0-becc-0022156e8794
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.68831");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2094");
  script_name("FreeBSD Ports: pecl-phar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: pecl-phar

CVE-2010-2094
Multiple format string vulnerabilities in the phar extension in PHP
5.3 before 5.3.2 allow context-dependent attackers to obtain sensitive
information (memory contents) and possibly execute arbitrary code via
a crafted phar:// URI that is not properly handled by the (1)
phar_stream_flush, (2) phar_wrapper_unlink, (3) phar_parse_url, or (4)
phar_wrapper_open_url functions in ext/phar/stream.c, and the (5)
phar_wrapper_open_dir function in ext/phar/dirstream.c, which triggers
errors in the php_stream_wrapper_log_error function.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-025-php-phar_wrapper_open_dir-format-string-vulnerability/index.htm");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-026-php-phar_wrapper_unlink-format-string-vulnerability/index.htm");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-027-php-phar_parse_url-format-string-vulnerabilities/index.htm");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-028-php-phar_wrapper_open_url-format-string-vulnerabilities/index.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/da3d381b-0ee6-11e0-becc-0022156e8794.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"pecl-phar");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package pecl-phar version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}