
R_MAX = 10
ALPHA = 0.8
BETA = 0.7
GAMMA = 2.0
MAX_PATH_LENGTH = 8
k = MAX_PATH_LENGTH

def update_pathR(old_pathR, R, w = 1.0):
  return old_pathR * ALPHA + R * w


def update_Ri(old_Ri, reward):
  return old_Ri * BETA + (1 - BETA) * reward


def calc_R(Re, Ri):
  return Re + Ri * (GAMMA / R_MAX + (R_MAX - GAMMA) * Re / (R_MAX * R_MAX))


def calc_reward(pathRs, k):
  return sum(pathRs) / (k * R_MAX)

# Simulation setup
epochs = 50
Re = R_MAX
Ri = 0

for epoch in range(1, epochs + 1):
  # 1. Calculate the current node R based on Re and Ri
  R = calc_R(Re, Ri)

  # 2. Simulate the path accumulation for a path of length MAX_PATH_LENGTH
  pathR = 0
  for hop in range(MAX_PATH_LENGTH):
    pathR = update_pathR(pathR, R)

  # 3. Node submits k = MAX_PATH_LENGTH paths, all reaching this maximum path score
  pathRs = [pathR] * k
  reward = calc_reward(pathRs, k)

  # 4. Update the intrinsic reputation (Ri) for the next epoch
  Ri = update_Ri(Ri, reward)

  if epoch <= 10 or epoch % 10 == 0:
    print(f"{epoch:<10} | {R:<18.5f} | {pathR:<20.5f} | {Ri:<10.5f}")