<template>
    <v-card>
      <v-layout>
        <v-main>
            <v-container class="fill-height">
              <v-responsive
                class="align-centerfill-height mx-auto"
                max-width="900"
                height="100vh"
              >
              <v-center>

              </v-center>
              <h1>Welcome to EmuC2</h1>
              <br>
              <p>{{ flag }}</p>
              <br/>
              <v-btn
                text
                color="primary"
                @click="authStore.logout()"
              >
                <a class="nav-item nav-link">Logout</a>
              </v-btn>
              </v-responsive>
            </v-container>
        </v-main>
      </v-layout> 
   </v-card>
    
    <AppFooter />
  
</template>

<script setup>
import { useAuthStore } from '@/stores';
import { fetchWrapper } from '@/helpers';

const authStore = useAuthStore();

let flag;
await fetchWrapper.get("/api/flag")
  .then(response => {
    if ("error" in response) {
      flag = response.error;
    } else if ("flag" in response) {
      flag = response.flag
    } else {
      flag = "Whoops... looks like the challenge is broken :/ (2)"
    }

    console.log(flag)
  })
  .catch(err => flag = "Whoops... looks like the challenge is broken :/ (1)")

</script>
