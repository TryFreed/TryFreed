import { serve } from 'https://deno.land/std@0.177.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const STRIPE_WEBHOOK_SECRET = Deno.env.get('STRIPE_WEBHOOK_SECRET')!
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

async function verifyStripeSignature(payload: string, sig: string, secret: string): Promise<boolean> {
  const parts = sig.split(',').reduce((acc: any, part: string) => {
    const [key, value] = part.split('=')
    acc[key.trim()] = value
    return acc
  }, {})

  const timestamp = parts['t']
  const signature = parts['v1']

  const signedPayload = timestamp + '.' + payload
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload))
  const expectedSig = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2, '0')).join('')

  return expectedSig === signature
}

async function findUserByEmail(supabase: any, email: string): Promise<any | null> {
  let page = 1
  const perPage = 1000
  while (true) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage })
    if (error) { console.error('[WEBHOOK] listUsers error:', error); break }
    if (!data?.users?.length) break
    const user = data.users.find((u: any) => u.email === email)
    if (user) return user
    if (data.users.length < perPage) break // última página
    page++
  }
  return null
}

async function activateSubscription(email: string): Promise<void> {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  const user = await findUserByEmail(supabase, email)
  if (!user) {
    console.log('[WEBHOOK] User not found for email:', email)
    return
  }
  const { error: updateErr } = await supabase
    .from('profiles')
    .upsert({ user_id: user.id, subscribed: true }, { onConflict: 'user_id' })
  if (updateErr) {
    console.error('[WEBHOOK] Error updating profile:', updateErr)
    return
  }
  console.log('[WEBHOOK] Subscription activated for:', email)
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' } })
  }

  try {
    const body = await req.text()
    const sig = req.headers.get('stripe-signature')

    if (!sig) {
      return new Response('No signature', { status: 400 })
    }

    const valid = await verifyStripeSignature(body, sig, STRIPE_WEBHOOK_SECRET)
    if (!valid) {
      console.error('[WEBHOOK] Invalid Stripe signature')
      return new Response('Invalid signature', { status: 400 })
    }

    const event = JSON.parse(body)
    console.log('[WEBHOOK] evento recebido:', event.type)
    console.log('[WEBHOOK] payment_status:', event.data.object.payment_status)

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object
      // Apple Pay às vezes tem payment_status='paid' em vez de status='complete'
      if (session.payment_status === 'paid' || session.status === 'complete') {
        const customerEmail = session.customer_email || session.customer_details?.email
        if (!customerEmail) {
          console.error('[WEBHOOK] No email in checkout session')
          return new Response('No email', { status: 400 })
        }
        await activateSubscription(customerEmail)
      } else {
        console.log('[WEBHOOK] Skipping — payment_status:', session.payment_status, 'status:', session.status)
      }
    }

    // Fallback para Apple Pay: payment_intent.succeeded pode chegar antes ou sem checkout.session
    if (event.type === 'payment_intent.succeeded') {
      const pi = event.data.object
      const email = pi.receipt_email
      if (email) {
        console.log('[WEBHOOK] payment_intent.succeeded fallback para:', email)
        await activateSubscription(email)
      } else {
        console.log('[WEBHOOK] payment_intent.succeeded sem receipt_email, ignorando')
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object
      const customerEmail = subscription.customer_email
      if (customerEmail) {
        const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        const user = await findUserByEmail(supabase, customerEmail)
        if (user) {
          await supabase
            .from('profiles')
            .update({ subscribed: false })
            .eq('user_id', user.id)
          console.log('[WEBHOOK] Subscription deactivated for:', customerEmail)
        }
      }
    }

    return new Response(JSON.stringify({ received: true }), {
      headers: { 'Content-Type': 'application/json' },
      status: 200
    })

  } catch (err) {
    console.error('[WEBHOOK] Webhook error:', err)
    return new Response('Webhook error', { status: 500 })
  }
})
