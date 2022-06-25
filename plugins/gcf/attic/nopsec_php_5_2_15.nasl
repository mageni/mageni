##############################################################################
# OpenVAS Vulnerability Test
#
# PHP Version 5.2 < 5.2.15 Multiple Vulnerabilities
#
# Authors:
# Songhan Yu <syu@nopsec.com>
#
# Copyright:
# Copyright (C) 2012 NopSec Inc.
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.110066");
  script_version("2020-04-27T09:38:31+0000");
  script_tag(name:"last_modification", value:"2020-04-28 10:10:27 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.8");
  script_cve_id("CVE-2010-3436", "CVE-2010-3709", "CVE-2010-4150",
                "CVE-2010-4697", "CVE-2010-4698", "CVE-2011-0752");
  script_bugtraq_id(44718, 44723, 45335, 45952, 46448);
  script_name("PHP Version 5.2 < 5.2.15 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 NopSec Inc.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.2.15 or later.");

  script_tag(name:"summary", value:"PHP 5.2 < 5.2.15 suffers from multiple vulnerabilities such as a crash
  in the zip extract method, NULL pointer dereference and stack-based buffer overflow.

  This VT has been replaced by the following VTs:

  - PHP 'phar_stream_flush' Format String Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.902317)

  - PHP 'filter_var()' function Stack Consumption Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.801547)

  - PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.801583)

  - PHP Zend and GD Multiple Denial of Service Vulnerabilities (OID: 1.3.6.1.4.1.25623.1.0.801586)

  - PHP 'extract()' Function Security Bypass Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.801731)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
