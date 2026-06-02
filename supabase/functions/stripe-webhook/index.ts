import { serve } from 'https://deno.land/std@0.177.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const STRIPE_WEBHOOK_SECRET = Deno.env.get('STRIPE_WEBHOOK_SECRET')!
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

// Stripe signature verification
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

serve(async (req) => {
  // CORS
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' } })
  }

  try {
    const body = await req.text()
    const sig = req.headers.get('stripe-signature')

    if (!sig) {
      return new Response('No signature', { status: 400 })
    }

    // Verify signature
    const valid = await verifyStripeSignature(body, sig, STRIPE_WEBHOOK_SECRET)
    if (!valid) {
      console.error('Invalid Stripe signature')
      return new Response('Invalid signature', { status: 400 })
    }

    const event = JSON.parse(body)
    console.log('Stripe event:', event.type)

    // Handle checkout.session.completed
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object
      const customerEmail = session.customer_email || session.customer_details?.email

      if (!customerEmail) {
        console.error('No email in checkout session')
        return new Response('No email', { status: 400 })
      }

      console.log('Activating subscription for:', customerEmail)

      // Init Supabase with service role (bypass RLS)
      const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

      // Find user by email
      const { data: users, error: userErr } = await supabase.auth.admin.listUsers()
      if (userErr) {
        console.error('Error listing users:', userErr)
        return new Response('Error', { status: 500 })
      }

      const user = users.users.find((u: any) => u.email === customerEmail)
      if (!user) {
        console.log('User not found for email:', customerEmail)
        // Store email for later activation when they sign up
        return new Response('User not found, will activate on signup', { status: 200 })
      }

      // Update profile
      const { error: updateErr } = await supabase
        .from('profiles')
        .upsert({ user_id: user.id, subscribed: true }, { onConflict: 'user_id' })

      if (updateErr) {
        console.error('Error updating profile:', updateErr)
        return new Response('Update error', { status: 500 })
      }

      console.log('Subscription activated for:', customerEmail)
    }

    // Handle customer.subscription.deleted (cancelamento)
    if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object
      const customerEmail = subscription.customer_email

      if (customerEmail) {
        const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        const { data: users } = await supabase.auth.admin.listUsers()
        const user = users?.users?.find((u: any) => u.email === customerEmail)

        if (user) {
          await supabase
            .from('profiles')
            .update({ subscribed: false })
            .eq('user_id', user.id)
          console.log('Subscription deactivated for:', customerEmail)
        }
      }
    }

    return new Response(JSON.stringify({ received: true }), {
      headers: { 'Content-Type': 'application/json' },
      status: 200
    })

  } catch (err) {
    console.error('Webhook error:', err)
    return new Response('Webhook error', { status: 500 })
  }
})
