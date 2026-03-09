/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isSafeRedirectTarget (toUrl: string): boolean {
  if (!toUrl) {
    return false
  }

  // Allow relative paths within this application but disallow protocol-relative URLs.
  if (toUrl.startsWith('/') && !toUrl.startsWith('//')) {
    return true
  }

  // For absolute URLs, only allow those that are on the explicit redirect allowlist.
  for (const allowedUrl of security.redirectAllowlist) {
    if (utils.startsWith(toUrl, allowedUrl)) {
      return true
    }
  }

  return false
}

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const rawTo = query.to
    if (typeof rawTo !== 'string') {
      res.status(406)
      return next(new Error('Unrecognized target URL for redirect: ' + rawTo))
    }
    const toUrl: string = rawTo
    if (security.isRedirectAllowed(toUrl) && isSafeRedirectTarget(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
