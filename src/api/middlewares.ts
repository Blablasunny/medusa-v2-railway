import {
  defineMiddlewares,
  authenticate,
  MedusaNextFunction,
  MedusaRequest,
  MedusaResponse,
} from "@medusajs/framework/http"
import { Modules } from "@medusajs/framework/utils"

async function denyManager(
  req: MedusaRequest,
  res: MedusaResponse,
  next: MedusaNextFunction
) {
  const actorId = (req as any).auth_context?.actor_id
  if (!actorId) return next()

  const userModule = req.scope.resolve(Modules.USER)
  const user = await userModule.retrieveUser(actorId)

  if (user.metadata?.role === "manager") {
    return res
      .status(403)
      .json({ message: "Роль manager не может выполнять это действие" })
  }
  next()
}

const adminAuth = authenticate("user", ["session", "bearer"])

export default defineMiddlewares({
  routes: [
    { matcher: /^\/admin\/products\/[^/]+$/, method: ["DELETE"], middlewares: [adminAuth, denyManager] },
    { matcher: /^\/admin\/users\/[^/]+$/, method: ["DELETE"], middlewares: [adminAuth, denyManager] },
    { matcher: /^\/admin\/invites$/, method: ["POST"], middlewares: [adminAuth, denyManager] },
  ],
})