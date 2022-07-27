##############################################################################
# OpenVAS Vulnerability Test
#
# PHP Version < 5.2.11 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.110176");
  script_version("2020-04-27T09:38:31+0000");
  script_tag(name:"last_modification", value:"2020-04-28 10:10:27 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293",
                "CVE-2009-3294", "CVE-2009-4018", "CVE-2009-5016");
  script_bugtraq_id(36449, 44889);
  script_name("PHP Version < 5.2.11 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 NopSec Inc.");

  script_tag(name:"solution", value:"Update PHP to version 5.2.11 or later.");

  script_tag(name:"summary", value:"PHP version smaller than 5.2.11 suffers from multiple vulnerabilities.

  This VT has been replaced by the following VTs:

  - PHP Multiple Vulnerabilities - Sep09 (OID: 1.3.6.1.4.1.25623.1.0.900871)

  - PHP 'tsrm_win32.c' Denial Of Service Vulnerability (Windows) (OID: 1.3.6.1.4.1.25623.1.0.900872)

  - PHP Multiple Vulnerabilities - Dec09 (OID: 1.3.6.1.4.1.25623.1.0.801060)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
