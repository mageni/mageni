###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssl_cert_expiry.nasl 14051 2019-03-08 09:12:38Z cfischer $
#
# SSL/TLS: Certificate Expiry
#
# Authors:
# George A. Theall, <theall@tifaware.com>
# Werner Koch <wk@gnupg.org>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# How far (in days) to warn of certificate expiry. [Hmmm, how often
# will scans be run and how quickly can people obtain new certs???]
lookahead = 60;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15901");
  script_version("$Revision: 14051 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 10:12:38 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Certificate Expiry");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"solution", value:"Purchase or generate a new SSL/TLS certificate to replace the existing one.");

  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate has already expired or will expire
  shortly.

  This NVT has been replaced by NVT 'SSL/TLS: Certificate Expired' (OID: 1.3.6.1.4.1.25623.1.0.103955).");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired or will expire shortly.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # with libraries >= 7 the more recent gb_ssl_cert_expired.nasl take this job.